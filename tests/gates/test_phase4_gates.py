"""GATE TESTS — Phase 4 (per-site security controls + per-site cron).

These tests are the security and correctness contract for Phase 4. They were
written before the implementation and encode decisions, not implementation
details, so a gate failing usually means the product regressed rather than that
the gate is out of date.

They are editable, and were immutable until 2026-08-15. Change one only when
the decision it pins has genuinely changed, never to make a red test green:
say in the commit which decision moved and why, and keep the gate asserting the
new one. A gate deleted or weakened to pass takes its invariant with it.

This file is deliberately self-contained: it depends only on the stdlib and the
`wpfy` package, never on other test modules or shared fixtures.

The two invariants this phase exists to protect:

    1. An access rule must be evaluated against the real client, and operator
       input must never become an nginx directive.

    A deny rule that matches Traefik's address instead of the visitor's blocks
    everyone or no one. Worse, a deny list evaluated against a spoofable header
    is an access-control bypass: the attacker chooses what wpfy thinks their
    address is. And because these rules are rendered into a config file that
    nginx executes, an unescaped quote or newline in a CIDR or user-agent
    pattern is remote configuration injection, not a formatting bug.

    2. A scheduled command runs inside its own site's container, and nowhere else.

    Cron is the one Phase 4 feature that executes operator-supplied strings. If a
    job can escape to the host, or reach a sibling site's container, per-site
    isolation is gone and one tenant owns the machine.

Invariants locked here:
  S1  The rendered security snippet resolves the real client IP (set_real_ip_from
      + real_ip_header) so deny rules act on the visitor, not the edge proxy.
  S2  The trusted-proxy source is never a wildcard. Trusting every source makes
      the forwarded header attacker-controlled, which turns the deny list into a
      bypass rather than a control.
  S3  Anti-vacuity for S1/S4: a legitimate CIDR really is emitted as a deny rule.
  S4  Hostile CIDR input is refused and never reaches the rendered config.
  S5  Hostile user-agent input is refused and never reaches the rendered config.
  S6  Anti-vacuity for S5: a legitimate user-agent pattern really is emitted.
  S7  Basic-auth passwords are never stored in cleartext anywhere under the site,
      and the htpasswd file is outside the document root.
  S8  Cloudflare-only is enforced at the edge (Traefik), not only in nginx, and
      the allow list is real Cloudflare space rather than a wildcard.
  S9  Turning a feature off removes its rules; rendering twice is byte-stable.
  S10 Enabling Cloudflare-only on a site that is not actually proxied produces a
      lockout warning rather than silently cutting the site off.

  C1  A due job executes through compose, scoped to its own site's project.
  C2  A job never executes on the host: no host shell, no crontab mutation.
  C3  A hostile service name cannot redirect execution at another container.
  C4  Anti-vacuity for C1: a job that is not due does not execute.
  C5  A disabled job never executes.
  C6  The schedule matcher is correct for *, lists, ranges, and steps.
  C7  Malformed schedules are refused at write time, not at fire time.
  C8  A site whose runtime is down is skipped, and not backfilled later.
  C9  Overlapping runs are prevented by a lock that survives a stale holder.
  C10 Job execution is bounded by a timeout.

Contract pinned by these gates (the actor must match these names):
  * module `wpfy.site_security` exposing `load_security(domain)`,
    `save_security(domain, config)`, `render_security(domain)`,
    `security_preflight(domain, change)`, `add_deny_ip(domain, cidr)`,
    `add_ua_block(domain, pattern)`, `set_basic_auth(domain, ...)`,
    `set_cloudflare_only(domain, enabled)`.
  * state file `<site>/security.json`; generated snippet
    `<site>/nginx/extra/wpfy-security.conf`; htpasswd at `<site>/nginx/htpasswd`.
  * module `wpfy.site_cron` exposing `load_cron(domain)`, `add_job(domain, ...)`,
    `schedule_matches(schedule, moment)`, `run_due(moment)`.
  * state file `<site>/cron.json`.
  * cron job fields: `id`, `schedule`, `command`, `service`, `enabled`, `timeout`.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path

import pytest

SEEDED_DOMAIN = "guard.example"
OTHER_DOMAIN = "victim.example"

SECURITY_SNIPPET = "wpfy-security.conf"

# Inputs that must never be accepted as a CIDR. Each one either terminates the
# generated directive and starts a new one, smuggles a newline, or is simply not
# an address. `wpfy_injected` is the marker: if it ever appears in the rendered
# config, operator input became nginx configuration.
HOSTILE_CIDRS = (
    "10.0.0.0/8; return 200 'wpfy_injected'",
    "10.0.0.0/8;\nallow all; # wpfy_injected",
    "10.0.0.0/8\ndeny all; # wpfy_injected",
    "10.0.0.0/8\x00wpfy_injected",
    '10.0.0.0/8" wpfy_injected "',
    "10.0.0.0/8}\nserver { # wpfy_injected",
    "$wpfy_injected",
    "not-an-ip",
    "999.999.999.999/8",
    "10.0.0.0/99",
    "",
    "   ",
    "0.0.0.0/0",  # a deny-everything rule is an operator footgun, not a control
)

# Inputs that must never be accepted as a user-agent pattern. The rendered form
# is a quoted regex, so a bare quote is a breakout.
HOSTILE_USER_AGENTS = (
    'evilbot" ) { return 200 "wpfy_injected"; } if ( $http_user_agent ~ "x',
    "evilbot\nreturn 200 'wpfy_injected';",
    "evilbot\x00wpfy_injected",
    'evilbot"; # wpfy_injected',
    "evilbot\\\nwpfy_injected",
    "evilbot}\nserver { # wpfy_injected",
    "",
    "   ",
)

# Service names a job must not be able to target. The first two are sibling
# sites' containers; the rest are shell/path escapes.
HOSTILE_SERVICES = (
    "victim-example-app",
    "../victim.example/app",
    "app; rm -rf /",
    "app\nwpfy_injected",
    "app\x00",
    "",
    "wpfy-traefik",
)

# (schedule, moment, expected) — the matcher's correctness table.
# Moments are (year, month, day, hour, minute).
SCHEDULE_CASES = (
    ("* * * * *", (2026, 7, 24, 10, 30), True),
    ("30 10 * * *", (2026, 7, 24, 10, 30), True),
    ("30 10 * * *", (2026, 7, 24, 10, 31), False),
    ("*/5 * * * *", (2026, 7, 24, 10, 30), True),
    ("*/5 * * * *", (2026, 7, 24, 10, 32), False),
    ("*/15 * * * *", (2026, 7, 24, 10, 45), True),
    ("0,30 * * * *", (2026, 7, 24, 10, 30), True),
    ("0,30 * * * *", (2026, 7, 24, 10, 15), False),
    ("10-20 * * * *", (2026, 7, 24, 10, 15), True),
    ("10-20 * * * *", (2026, 7, 24, 10, 21), False),
    ("0 0 1 * *", (2026, 7, 1, 0, 0), True),
    ("0 0 1 * *", (2026, 7, 2, 0, 0), False),
    # 2026-07-24 is a Friday (weekday 5 in cron's 0=Sunday numbering).
    ("0 12 * * 5", (2026, 7, 24, 12, 0), True),
    ("0 12 * * 1", (2026, 7, 24, 12, 0), False),
    ("0 12 * 7 *", (2026, 7, 24, 12, 0), True),
    ("0 12 * 8 *", (2026, 7, 24, 12, 0), False),
)

MALFORMED_SCHEDULES = (
    "",
    "* * * *",
    "* * * * * *",
    "60 * * * *",
    "* 24 * * *",
    "* * 32 * *",
    "* * * 13 *",
    "* * * * 8",
    "*/0 * * * *",
    "20-10 * * * *",
    "abc * * * *",
    "* * * * *; rm -rf /",
    "*\n* * * *",
)


# --------------------------------------------------------------------------
# Self-contained harness
# --------------------------------------------------------------------------

_GATE_ENV = (
    "WPFY_INSTALL_ROOT",
    "WPFY_CONFIG_DIR",
    "WPFY_STATE_DIR",
    "WPFY_LOG_DIR",
    "WPFY_SKIP_RUNTIME",
    "WPFY_SKIP_WORDPRESS_DOWNLOAD",
    "WPFY_ACME_EMAIL",
)

_PATH_FIELDS = ("install_root", "config_dir", "state_dir", "log_dir")


class _Recorder:
    """Records every host command and lets a test choose which ones fail."""

    def __init__(self) -> None:
        self.calls: list[dict] = []
        self.fail_predicate = None

    def reset(self) -> None:
        self.calls.clear()

    def __call__(self, args, **kwargs):
        argv = [str(item) for item in args] if isinstance(args, (list, tuple)) else [str(args)]
        stdin = kwargs.get("input")
        self.calls.append({
            "argv": argv,
            "stdin": stdin if isinstance(stdin, str) else "",
            "timeout": kwargs.get("timeout"),
        })
        if self.fail_predicate is not None and self.fail_predicate(argv):
            return subprocess.CompletedProcess(argv, 1, "", "Error: not running\n")
        return subprocess.CompletedProcess(argv, 0, "", "")

    def joined(self) -> list[str]:
        return [" ".join(call["argv"]) for call in self.calls]

    def any_matching(self, *tokens: str) -> bool:
        return any(all(token in line for token in tokens) for line in self.joined())


@contextmanager
def _gate_home(tmp_path, monkeypatch):
    import wpfy.registry
    import wpfy.settings
    import wpfy.site_runtime

    paths = wpfy.settings.PATHS
    previous_env = {name: os.environ.get(name) for name in _GATE_ENV}
    previous_paths = {field: getattr(paths, field) for field in _PATH_FIELDS}
    previous_registry = wpfy.registry._REGISTRY

    os.environ.update({
        "WPFY_INSTALL_ROOT": str(tmp_path / "install"),
        "WPFY_CONFIG_DIR": str(tmp_path / "config"),
        "WPFY_STATE_DIR": str(tmp_path / "state"),
        "WPFY_LOG_DIR": str(tmp_path / "log"),
        "WPFY_SKIP_WORDPRESS_DOWNLOAD": "1",
        "WPFY_ACME_EMAIL": "gate@example.com",
    })
    os.environ.pop("WPFY_SKIP_RUNTIME", None)
    for field in _PATH_FIELDS:
        object.__setattr__(paths, field, os.environ[f"WPFY_{field.upper()}"])
    wpfy.registry._REGISTRY = None

    recorder = _Recorder()
    import shutil as _shutil

    monkeypatch.setattr(subprocess, "run", recorder)
    monkeypatch.setattr(
        _shutil,
        "which",
        lambda name, *args, **kwargs: f"/usr/bin/{name}" if name == "docker" else None,
    )
    wpfy.site_runtime.docker_available.cache_clear()
    wpfy.site_runtime.docker_available()
    recorder.reset()

    try:
        yield paths, recorder
    finally:
        for field, value in previous_paths.items():
            object.__setattr__(paths, field, value)
        wpfy.registry._REGISTRY = previous_registry
        wpfy.site_runtime.docker_available.cache_clear()
        for name, value in previous_env.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value


@pytest.fixture
def gate_home(tmp_path, monkeypatch):
    with _gate_home(tmp_path, monkeypatch) as ctx:
        yield ctx


def _seed_site(paths, *, domain=SEEDED_DOMAIN, project=None) -> Path:
    site = Path(paths.sites_dir) / domain
    (site / "nginx" / "extra").mkdir(parents=True, exist_ok=True)
    (site / "php").mkdir(parents=True, exist_ok=True)
    (site / "app").mkdir(parents=True, exist_ok=True)
    (site / ".env").write_text(
        f"DOMAIN={domain}\n"
        "SITE_FLAVOR=wp\n"
        f"COMPOSE_PROJECT_NAME={project or domain.replace('.', '-')}\n"
        "APP_ROOT=/var/www/html\n"
        "PHP_VERSION=8.4\n"
        "SITE_UID=1700\n"
        "LETSENCRYPT_MODE=disabled\n"
        "PAGE_CACHE=none\n"
        f"DB_NAME={domain.split('.')[0]}\n"
        f"DB_USER={domain.split('.')[0]}\n"
        "DB_PASSWORD=guard-gate-pw\n"
        "DB_ROOT_PASSWORD=guard-gate-root-pw\n",
        encoding="utf-8",
    )
    (site / "compose.yaml").write_text("services: {}\n", encoding="utf-8")
    (site / "nginx" / "default.conf").write_text("server {\n    listen 8080;\n}\n", encoding="utf-8")
    (site / "nginx" / "extra" / "custom.conf").write_text("", encoding="utf-8")
    return site


def _rendered_compose(domain: str = SEEDED_DOMAIN) -> str:
    """Render the compose file the way the scaffold does, from the site's .env."""
    from wpfy.site_definition import SiteDefinition
    from wpfy.site_layout import compose_content
    from wpfy.site_paths import env_path, read_env

    spec = SiteDefinition.from_env(domain, read_env(env_path(domain)))
    return compose_content(spec)


def _snippet_text(paths, domain: str = SEEDED_DOMAIN) -> str:
    path = Path(paths.sites_dir) / domain / "nginx" / "extra" / SECURITY_SNIPPET
    return path.read_text(encoding="utf-8") if path.exists() else ""


def _directive_lines(text: str) -> list[str]:
    """Non-comment, non-blank lines — i.e. the lines nginx will act on."""
    lines = []
    for raw in text.splitlines():
        stripped = raw.strip()
        if stripped and not stripped.startswith("#"):
            lines.append(stripped)
    return lines


def _attempt(callable_, *args):
    """Call an operation that must reject bad input.

    Accepts either exception-raising or result-returning styles, so the gate
    pins the security outcome rather than the error-handling idiom. Returns
    True if the input was refused.
    """
    try:
        result = callable_(*args)
    except (ValueError, TypeError, OSError):
        return True
    exit_code = getattr(result, "exit_code", None)
    if exit_code is not None:
        return exit_code != 0
    if isinstance(result, bool):
        return not result
    # A silent success on hostile input is exactly the failure being tested.
    return False


def _moment(parts) -> datetime:
    return datetime(*parts)


# --------------------------------------------------------------------------
# S1 / S2 / S3 — deny rules must act on the real client, unspoofably
# --------------------------------------------------------------------------

def test_gate_security_snippet_resolves_real_client_ip(gate_home):
    """S1: without real-IP resolution every deny matches the edge proxy.

    Behind Traefik the connecting address is always the proxy's. A deny list
    compared against that address blocks every visitor or none of them.
    """
    from wpfy import site_security

    paths, _ = gate_home
    _seed_site(paths)
    site_security.add_deny_ip(SEEDED_DOMAIN, "203.0.113.7/32")
    site_security.render_security(SEEDED_DOMAIN)
    snippet = _snippet_text(paths)

    assert snippet.strip(), "no security snippet was rendered"
    assert "set_real_ip_from" in snippet, (
        "snippet has no set_real_ip_from: deny rules would match Traefik's address"
    )
    assert "real_ip_header" in snippet, (
        "snippet has no real_ip_header: the forwarded client address is never read"
    )


def test_gate_real_ip_trusted_source_is_never_a_wildcard(gate_home):
    """S2: trusting any source makes the client's own header authoritative.

    If set_real_ip_from covers 0.0.0.0/0, a visitor can send their own
    X-Forwarded-For and choose the address wpfy evaluates the deny list
    against. That converts an access control into an access-control bypass.
    """
    from wpfy import site_security

    paths, _ = gate_home
    _seed_site(paths)
    site_security.add_deny_ip(SEEDED_DOMAIN, "203.0.113.7/32")
    site_security.render_security(SEEDED_DOMAIN)
    snippet = _snippet_text(paths)

    trusted = re.findall(r"set_real_ip_from\s+([^;]+);", snippet)
    assert trusted, "no set_real_ip_from source found"
    for source in trusted:
        value = source.strip()
        assert value not in {"0.0.0.0/0", "::/0", "all", "any"}, (
            f"set_real_ip_from {value} trusts every client: forwarded headers become spoofable"
        )


def test_gate_valid_cidr_is_actually_denied(gate_home):
    """S3: anti-vacuity — a rejection gate is worthless if nothing is accepted."""
    from wpfy import site_security

    paths, _ = gate_home
    _seed_site(paths)
    site_security.add_deny_ip(SEEDED_DOMAIN, "203.0.113.7/32")
    site_security.add_deny_ip(SEEDED_DOMAIN, "198.51.100.0/24")
    site_security.render_security(SEEDED_DOMAIN)
    snippet = _snippet_text(paths)

    assert re.search(r"deny\s+203\.0\.113\.7(/32)?\s*;", snippet), (
        f"single-host deny rule missing from snippet:\n{snippet}"
    )
    assert re.search(r"deny\s+198\.51\.100\.0/24\s*;", snippet), (
        f"network deny rule missing from snippet:\n{snippet}"
    )


@pytest.mark.parametrize("payload", HOSTILE_CIDRS)
def test_gate_hostile_cidr_never_reaches_nginx_config(gate_home, payload):
    """S4: an unescaped CIDR is remote nginx-config injection.

    The rendered file is executed by nginx. A payload that closes the directive
    and opens another can add `allow all`, a `return`, or a whole new server
    block. The input must be refused, and the config must be untouched.
    """
    from wpfy import site_security

    paths, _ = gate_home
    _seed_site(paths)
    site_security.render_security(SEEDED_DOMAIN)
    before = _snippet_text(paths)

    refused = _attempt(site_security.add_deny_ip, SEEDED_DOMAIN, payload)
    site_security.render_security(SEEDED_DOMAIN)
    after = _snippet_text(paths)

    assert refused, f"hostile CIDR was accepted: {payload!r}"
    assert "wpfy_injected" not in after, (
        f"injected marker reached the nginx config for {payload!r}:\n{after}"
    )
    assert after == before, (
        f"config changed after a refused CIDR {payload!r}:\n--- before ---\n{before}\n--- after ---\n{after}"
    )
    stored = json.dumps(site_security.load_security(SEEDED_DOMAIN), default=str)
    assert "wpfy_injected" not in stored, (
        f"hostile CIDR was persisted to security.json for {payload!r}"
    )


@pytest.mark.parametrize("payload", HOSTILE_USER_AGENTS)
def test_gate_hostile_user_agent_never_reaches_nginx_config(gate_home, payload):
    """S5: the UA pattern is rendered inside a quoted regex, so a quote escapes.

    Same class as S4: a bare `"` ends the pattern and the rest of the payload is
    parsed as configuration.
    """
    from wpfy import site_security

    paths, _ = gate_home
    _seed_site(paths)
    site_security.render_security(SEEDED_DOMAIN)
    before = _snippet_text(paths)

    refused = _attempt(site_security.add_ua_block, SEEDED_DOMAIN, payload)
    site_security.render_security(SEEDED_DOMAIN)
    after = _snippet_text(paths)

    assert refused, f"hostile user-agent was accepted: {payload!r}"
    assert "wpfy_injected" not in after, (
        f"injected marker reached the nginx config for {payload!r}:\n{after}"
    )
    assert after == before, (
        f"config changed after a refused user-agent {payload!r}"
    )


def test_gate_valid_user_agent_is_actually_blocked(gate_home):
    """S6: anti-vacuity for S5."""
    from wpfy import site_security

    paths, _ = gate_home
    _seed_site(paths)
    site_security.add_ua_block(SEEDED_DOMAIN, "EvilBot")
    site_security.render_security(SEEDED_DOMAIN)
    snippet = _snippet_text(paths)

    assert "EvilBot" in snippet, f"accepted user-agent pattern was not rendered:\n{snippet}"
    assert "http_user_agent" in snippet, (
        "user-agent block does not test $http_user_agent, so it blocks nothing"
    )
    assert "403" in snippet or "444" in snippet, (
        "user-agent block never denies the request"
    )


# --------------------------------------------------------------------------
# S7 — basic auth
# --------------------------------------------------------------------------

def test_gate_basic_auth_password_is_never_stored_in_cleartext(gate_home):
    """S7: a recoverable panel-set password is a credential leak.

    The htpasswd file must hold a hash, security.json must not hold the
    password at all, and nothing under the site directory may contain it.
    """
    from wpfy import site_security

    paths, _ = gate_home
    site = _seed_site(paths)
    secret = "Gate-BasicAuth-Secret-9173"

    site_security.set_basic_auth(SEEDED_DOMAIN, enabled=True, username="operator", password=secret)
    site_security.render_security(SEEDED_DOMAIN)

    offenders = []
    for path in site.rglob("*"):
        if not path.is_file():
            continue
        try:
            body = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if secret in body:
            offenders.append(str(path.relative_to(site)))

    assert not offenders, f"basic-auth password stored in cleartext in: {offenders}"

    stored = json.dumps(site_security.load_security(SEEDED_DOMAIN), default=str)
    assert secret not in stored, "basic-auth password persisted in security.json"


def test_gate_htpasswd_file_is_outside_the_document_root(gate_home):
    """S7: an htpasswd file under app/ is fetchable over HTTP.

    The document root is served. A credential file inside it can be downloaded
    and cracked offline, and it would also land in every backup of app/.
    """
    from wpfy import site_security

    paths, _ = gate_home
    site = _seed_site(paths)
    site_security.set_basic_auth(SEEDED_DOMAIN, enabled=True, username="operator", password="Gate-Pw-4482")
    site_security.render_security(SEEDED_DOMAIN)

    app_dir = site / "app"
    leaked = [str(p.relative_to(site)) for p in app_dir.rglob("*") if p.is_file() and "htpasswd" in p.name]
    assert not leaked, f"htpasswd file is inside the served document root: {leaked}"

    expected = site / "nginx" / "htpasswd"
    assert expected.exists(), f"expected htpasswd at {expected}, which the snippet can reference"

    snippet = _snippet_text(paths)
    assert "auth_basic" in snippet, "basic auth enabled but no auth_basic directive rendered"
    assert "auth_basic_user_file" in snippet, "no auth_basic_user_file directive rendered"


# --------------------------------------------------------------------------
# S8 / S10 — Cloudflare-only is an edge control
# --------------------------------------------------------------------------

def test_gate_cloudflare_only_is_enforced_at_the_edge(gate_home):
    """S8: nginx-only enforcement still lets traffic reach the origin.

    The point of Cloudflare-only is that non-Cloudflare traffic never touches
    the site. That requires a Traefik middleware on the router, not just a deny
    inside the site's own nginx.
    """
    from wpfy import site_security

    paths, _ = gate_home
    _seed_site(paths)
    site_security.set_cloudflare_only(SEEDED_DOMAIN, True)
    site_security.render_security(SEEDED_DOMAIN)

    compose = _rendered_compose()

    assert "ipallowlist" in compose.lower(), (
        "Cloudflare-only enabled but no Traefik ipAllowList middleware on the router:\n"
        "non-Cloudflare traffic still reaches the origin"
    )

    allow_sources = " ".join(
        line for line in compose.splitlines() if "ipallowlist" in line.lower()
    )
    assert "0.0.0.0/0" not in allow_sources, "edge allow list is a wildcard, so it allows everything"


def test_gate_cloudflare_only_allow_list_is_real_cloudflare_space(gate_home):
    """S8: an allow list built from the wrong ranges locks the operator out."""
    from wpfy import cloudflare_ranges, site_security

    paths, _ = gate_home
    _seed_site(paths)
    site_security.set_cloudflare_only(SEEDED_DOMAIN, True)
    site_security.render_security(SEEDED_DOMAIN)

    compose = _rendered_compose()

    present = [cidr for cidr in cloudflare_ranges.CLOUDFLARE_IPV4 if cidr in compose]
    assert len(present) >= 5, (
        f"only {len(present)} published Cloudflare IPv4 ranges appear in the edge allow list; "
        "a partial list silently blocks legitimate Cloudflare edges"
    )


def test_gate_cloudflare_only_warns_before_locking_out_an_unproxied_site(gate_home):
    """S10: enabling this on a direct-DNS site takes it offline immediately.

    The operator must be told before the change applies, not discover it from a
    dead site. The warning is the deliverable here.
    """
    from wpfy import site_security

    paths, _ = gate_home
    _seed_site(paths)

    os.environ["WPFY_TEST_DNS_IPS"] = "203.0.113.9"
    try:
        preflight = site_security.security_preflight(SEEDED_DOMAIN, {"cloudflare_only": True})
    finally:
        os.environ.pop("WPFY_TEST_DNS_IPS", None)

    warnings = getattr(preflight, "warnings", None)
    if warnings is None and isinstance(preflight, dict):
        warnings = preflight.get("warnings")
    assert warnings, (
        "no lockout warning when enabling Cloudflare-only on a site whose DNS does "
        "not resolve to Cloudflare"
    )
    text = " ".join(str(item) for item in warnings).lower()
    assert "cloudflare" in text, f"warning does not mention Cloudflare: {warnings}"


# --------------------------------------------------------------------------
# S9 — regeneration contract
# --------------------------------------------------------------------------

def test_gate_disabling_security_features_removes_their_rules(gate_home):
    """S9: a rule that outlives its setting is a rule nobody knows is active."""
    from wpfy import site_security

    paths, _ = gate_home
    _seed_site(paths)

    site_security.add_deny_ip(SEEDED_DOMAIN, "203.0.113.7/32")
    site_security.add_ua_block(SEEDED_DOMAIN, "EvilBot")
    site_security.set_basic_auth(SEEDED_DOMAIN, enabled=True, username="operator", password="Gate-Pw-7781")
    site_security.render_security(SEEDED_DOMAIN)
    enabled = _snippet_text(paths)
    assert "203.0.113.7" in enabled and "EvilBot" in enabled and "auth_basic" in enabled

    site_security.remove_deny_ip(SEEDED_DOMAIN, "203.0.113.7/32")
    site_security.remove_ua_block(SEEDED_DOMAIN, "EvilBot")
    site_security.set_basic_auth(SEEDED_DOMAIN, enabled=False)
    site_security.render_security(SEEDED_DOMAIN)
    disabled = _snippet_text(paths)

    assert "203.0.113.7" not in disabled, "deny rule survived its removal"
    assert "EvilBot" not in disabled, "user-agent block survived its removal"
    assert "auth_basic" not in disabled, "auth_basic survived disabling basic auth"


def test_gate_security_snippet_is_byte_stable_across_renders(gate_home):
    """S9: `wpfy refresh` must reproduce generated files exactly."""
    from wpfy import site_security

    paths, _ = gate_home
    _seed_site(paths)
    site_security.add_deny_ip(SEEDED_DOMAIN, "198.51.100.0/24")
    site_security.add_ua_block(SEEDED_DOMAIN, "EvilBot")

    site_security.render_security(SEEDED_DOMAIN)
    first = _snippet_text(paths)
    site_security.render_security(SEEDED_DOMAIN)
    second = _snippet_text(paths)
    site_security.render_security(SEEDED_DOMAIN)
    third = _snippet_text(paths)

    assert first == second == third, "security snippet is not byte-stable across renders"


def test_gate_security_snippet_emits_no_stray_directives_when_unconfigured(gate_home):
    """S9: an empty configuration must not deny, allow, or authenticate anything."""
    from wpfy import site_security

    paths, _ = gate_home
    _seed_site(paths)
    site_security.render_security(SEEDED_DOMAIN)
    lines = _directive_lines(_snippet_text(paths))

    for line in lines:
        assert not line.startswith("deny "), f"unconfigured site has a deny rule: {line}"
        assert not line.startswith("allow "), f"unconfigured site has an allow rule: {line}"
        assert not line.startswith("auth_basic"), f"unconfigured site requires auth: {line}"


# --------------------------------------------------------------------------
# C1 / C2 / C3 / C4 / C5 — cron execution boundary
# --------------------------------------------------------------------------

def test_gate_due_cron_job_runs_inside_its_own_site_container(gate_home):
    """C1: the job must execute through compose, scoped to its own project."""
    from wpfy import site_cron

    paths, recorder = gate_home
    _seed_site(paths, project="guard-example")
    site_cron.add_job(SEEDED_DOMAIN, schedule="* * * * *", command="wp cron event run --due-now", service="app")

    recorder.reset()
    site_cron.run_due(_moment((2026, 7, 24, 10, 30)))

    assert recorder.calls, "a due job produced no execution at all"
    lines = recorder.joined()
    executed = [line for line in lines if "exec" in line]
    assert executed, f"no compose exec issued for a due job; calls were:\n" + "\n".join(lines)
    assert any("compose" in line for line in executed), (
        f"job did not run through docker compose:\n" + "\n".join(executed)
    )
    assert any("guard-example" in line for line in executed), (
        f"job execution is not scoped to the site's own compose project:\n" + "\n".join(executed)
    )


def test_gate_cron_never_executes_on_the_host(gate_home):
    """C2: a job escaping to the host ends per-site isolation for the machine.

    Also pins the ADR decision: no host crontab is ever mutated.
    """
    from wpfy import site_cron

    paths, recorder = gate_home
    _seed_site(paths)
    site_cron.add_job(SEEDED_DOMAIN, schedule="* * * * *", command="wp cron event run --due-now", service="app")

    recorder.reset()
    site_cron.run_due(_moment((2026, 7, 24, 10, 30)))

    for call in recorder.calls:
        argv = call["argv"]
        assert argv, "empty command recorded"
        program = Path(argv[0]).name
        assert program in {"docker", "docker-compose"}, (
            f"cron ran a non-container program on the host: {argv}"
        )
        joined = " ".join(argv)
        assert "crontab" not in joined, f"cron mutated the host crontab: {argv}"
        assert "/etc/cron" not in joined, f"cron wrote into host cron directories: {argv}"
        assert "systemctl" not in joined, f"cron touched host services: {argv}"


@pytest.mark.parametrize("service", HOSTILE_SERVICES)
def test_gate_hostile_cron_service_cannot_redirect_execution(gate_home, service):
    """C3: a crafted service name must not reach a sibling site's container.

    `docker exec <name>` takes a container name, so an unvalidated service
    field lets one tenant execute inside another tenant's container.
    """
    from wpfy import site_cron

    paths, recorder = gate_home
    _seed_site(paths, project="guard-example")
    _seed_site(paths, domain=OTHER_DOMAIN, project="victim-example")

    refused = _attempt(
        lambda: site_cron.add_job(
            SEEDED_DOMAIN, schedule="* * * * *", command="echo hi", service=service
        )
    )

    recorder.reset()
    site_cron.run_due(_moment((2026, 7, 24, 10, 30)))
    lines = recorder.joined()

    assert refused, f"hostile cron service was accepted: {service!r}"
    for line in lines:
        assert "victim-example" not in line, (
            f"cron reached another site's container via service {service!r}: {line}"
        )
        assert "wpfy-traefik" not in line, (
            f"cron reached the shared edge proxy via service {service!r}: {line}"
        )


def test_gate_cron_job_that_is_not_due_does_not_run(gate_home):
    """C4: anti-vacuity — a scheduler that never fires would pass C1..C3."""
    from wpfy import site_cron

    paths, recorder = gate_home
    _seed_site(paths)
    site_cron.add_job(SEEDED_DOMAIN, schedule="30 10 * * *", command="echo hi", service="app")

    recorder.reset()
    site_cron.run_due(_moment((2026, 7, 24, 11, 31)))

    assert not any("exec" in line for line in recorder.joined()), (
        "a job ran at a moment its schedule does not match"
    )


def test_gate_disabled_cron_job_never_runs(gate_home):
    """C5: disabling is a control operators rely on to stop a misbehaving job."""
    from wpfy import site_cron

    paths, recorder = gate_home
    _seed_site(paths)
    job = site_cron.add_job(
        SEEDED_DOMAIN, schedule="* * * * *", command="echo wpfy_should_not_run", service="app"
    )
    job_id = getattr(job, "id", None) or (job.get("id") if isinstance(job, dict) else None)
    assert job_id, "add_job did not return an identifiable job"

    site_cron.set_enabled(SEEDED_DOMAIN, job_id, False)

    recorder.reset()
    site_cron.run_due(_moment((2026, 7, 24, 10, 30)))

    assert not any("wpfy_should_not_run" in line for line in recorder.joined()), (
        "a disabled job still executed"
    )


# --------------------------------------------------------------------------
# C6 / C7 — the schedule matcher
# --------------------------------------------------------------------------

@pytest.mark.parametrize("schedule,moment,expected", SCHEDULE_CASES)
def test_gate_schedule_matcher_is_correct(gate_home, schedule, moment, expected):
    """C6: a wrong matcher either never runs a job or runs it every minute."""
    from wpfy import site_cron

    actual = site_cron.schedule_matches(schedule, _moment(moment))
    assert bool(actual) is expected, (
        f"schedule {schedule!r} at {_moment(moment).isoformat()}: expected {expected}, got {actual}"
    )


@pytest.mark.parametrize("schedule", MALFORMED_SCHEDULES)
def test_gate_malformed_schedule_is_refused_at_write_time(gate_home, schedule):
    """C7: a bad schedule must fail when the operator sets it.

    Deferring validation to the minute tick turns a typo into a silent
    never-runs job, or an exception inside the shared scheduler that stops
    other sites' jobs from running.
    """
    from wpfy import site_cron

    paths, _ = gate_home
    _seed_site(paths)

    refused = _attempt(
        lambda: site_cron.add_job(
            SEEDED_DOMAIN, schedule=schedule, command="echo hi", service="app"
        )
    )
    assert refused, f"malformed schedule was accepted: {schedule!r}"

    stored = json.dumps(site_cron.load_cron(SEEDED_DOMAIN), default=str)
    assert "rm -rf" not in stored, f"dangerous schedule persisted: {schedule!r}"


# --------------------------------------------------------------------------
# C8 / C9 / C10 — scheduler robustness
# --------------------------------------------------------------------------

def test_gate_runtime_down_site_is_skipped_and_not_backfilled(gate_home):
    """C8: a stopped site must not accumulate a queue that stampedes on start.

    Backfilling missed runs means starting a site after a week runs 2000 jobs at
    once. The documented behaviour is skip-and-log.
    """
    from wpfy import site_cron

    paths, recorder = gate_home
    _seed_site(paths)
    site_cron.add_job(SEEDED_DOMAIN, schedule="* * * * *", command="echo hi", service="app")

    recorder.fail_predicate = lambda argv: "exec" in argv
    recorder.reset()
    site_cron.run_due(_moment((2026, 7, 24, 10, 30)))
    first_attempts = len([line for line in recorder.joined() if "exec" in line])

    recorder.fail_predicate = None
    recorder.reset()
    site_cron.run_due(_moment((2026, 7, 24, 10, 31)))
    second_attempts = len([line for line in recorder.joined() if "exec" in line])

    assert first_attempts >= 1, "no execution attempt was made at all"
    assert second_attempts <= first_attempts, (
        f"missed runs were backfilled: {first_attempts} attempt(s) then {second_attempts}"
    )


def test_gate_overlapping_cron_runs_are_prevented_by_a_lock(gate_home):
    """C9: a slow job re-entered every minute exhausts the site's resources."""
    from wpfy import site_cron

    paths, recorder = gate_home
    site = _seed_site(paths)
    site_cron.add_job(SEEDED_DOMAIN, schedule="* * * * *", command="echo hi", service="app")

    recorder.reset()
    site_cron.run_due(_moment((2026, 7, 24, 10, 30)))

    locks = [p for p in site.rglob("*") if p.is_file() and "lock" in p.name.lower()]
    state_locks = [
        p for p in Path(paths.state_dir).rglob("*") if p.is_file() and "lock" in p.name.lower()
    ]
    assert locks or state_locks, (
        "no lock file was created for a cron run, so a slow job can be re-entered "
        "on the next minute tick"
    )


def test_gate_cron_execution_is_bounded_by_a_timeout(gate_home):
    """C10: an unbounded job blocks the shared minute tick for every site."""
    from wpfy import site_cron

    paths, recorder = gate_home
    _seed_site(paths)
    site_cron.add_job(
        SEEDED_DOMAIN, schedule="* * * * *", command="echo hi", service="app", timeout=30
    )

    recorder.reset()
    site_cron.run_due(_moment((2026, 7, 24, 10, 30)))

    exec_calls = [call for call in recorder.calls if "exec" in " ".join(call["argv"])]
    assert exec_calls, "no exec call recorded"
    assert any(call["timeout"] for call in exec_calls), (
        "cron exec was issued with no timeout: one hung job stalls the shared tick"
    )


def test_gate_cron_command_is_never_interpolated_into_a_host_shell(gate_home):
    """C2/C3 corollary: the command must be argv to the container, not host shell.

    If the command string is pasted into `sh -c` on the host, every job is a
    host command-injection primitive regardless of how the service is validated.
    """
    from wpfy import site_cron

    paths, recorder = gate_home
    _seed_site(paths)
    marker = "wpfy_marker_$(id -u)"
    site_cron.add_job(SEEDED_DOMAIN, schedule="* * * * *", command=f"echo {marker}", service="app")

    recorder.reset()
    site_cron.run_due(_moment((2026, 7, 24, 10, 30)))

    for call in recorder.calls:
        argv = call["argv"]
        program = Path(argv[0]).name
        assert program not in {"sh", "bash", "zsh", "dash"}, (
            f"cron invoked a host shell: {argv}"
        )
        assert not (len(argv) >= 2 and argv[1] == "-c" and program != "docker"), (
            f"cron used a host shell -c form: {argv}"
        )
