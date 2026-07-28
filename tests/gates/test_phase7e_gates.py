"""OPUS-OWNED IMMUTABLE GATE TESTS — Phase 7e (fail2ban and WordPress hardening).

DO NOT EDIT, SKIP, XFAIL, PARAMETRIZE AWAY, OR DELETE ANYTHING IN THIS FILE.

These tests are the security and correctness contract for Phase 7e. They are
written by the orchestrator before implementation and are verified byte-identical
(SHA-256 baseline) as a precondition for accepting the phase. If you believe a
gate asserts the wrong thing, escalate with evidence — do not edit the gate.

This file is deliberately self-contained: it depends only on the stdlib and the
`wpfy` package, never on other test modules or shared fixtures.

What this phase can get wrong that nothing else catches:

    fail2ban is the first thing wpfy has built whose entire value lives in the
    agreement between two artifacts it does not run: a log line nginx writes,
    and a regular expression fail2ban reads. Everything else in this project
    fails loudly — a bad compose file will not start, a bad nginx directive will
    not reload. **A fail2ban filter that matches nothing fails silently, looks
    installed, reports "0 currently banned" forever, and is indistinguishable
    from a quiet week.** That is gate B4 and it is the one gate a plausible
    wrong implementation fails.

    Three more things go wrong here and nowhere else:

    1. **There is nothing for fail2ban to read today.** Every site's nginx logs
       to container stdout through the json-file driver; no access log reaches
       the host. So this phase must put one there, which is a compose change,
       which means existing sites need recreating.
    2. **The banned address must be the real client.** nginx sits behind
       Traefik, so without `real_ip` the access log records the *edge proxy's*
       address on every line. A fail2ban jail reading that log would ban Traefik
       and take every site on the box offline at once. This is the same
       prerequisite Phase 7d needed for its rate-limit key, and here it is the
       difference between a security feature and an outage.
    3. **`INPUT` is the wrong chain.** Traffic destined for a published
       container port is DNAT'd and traverses `FORWARD`, not `INPUT`, so the
       stock fail2ban iptables action silently bans nothing on a Docker host.
       `DOCKER-USER` is the chain Docker documents for exactly this.

    And one footgun this project has already been bitten by: a generated file
    that is bind-mounted **individually** must be written in place. `os.replace`
    allocates a new inode, the mount keeps pointing at the old one, and the
    container reads stale content forever while the file on disk looks correct.
    Gate H5 checks the inode directly.

Invariants locked here:
  L1   Each site writes an access log to a host path, per-site, never shared.
  L2   The log line carries the real client address, not the edge proxy's.
  L3   The log is rotated; an unbounded access log is a disk-fill outage.
  L4   The log path is not world-readable.
  B1   fail2ban integration is opt-in and off by default.
  B2   Enabling refuses cleanly when fail2ban is absent, leaving no partial state.
  B3   Anti-vacuity for B1/B2: with fail2ban present, enabling writes a filter
       and a jail.
  B4   The generated filter actually matches the log lines wpfy's own nginx
       writes, and does not match a successful request.
  B5   The jail points at the log the site actually writes.
  B6   The ban action targets `DOCKER-USER`, never `INPUT`.
  B7   Enabling twice is enabling once.
  B8   Disabling removes everything and is idempotent.
  B9   Nothing attacker-influenced can inject into the generated fail2ban config.
  H1   `install.php` and `upgrade.php` are refused.
  H2   Backup-plugin directories are refused.
  H3   The deprecated XSS filter is explicitly disabled, not left unset.
  H4   Anti-vacuity for H1-H3: ordinary WordPress paths still reach PHP.
  H5   Individually bind-mounted generated files keep their inode across a
       re-render.

Contract pinned by these gates (the actor must match these names exactly):

  `wpfy.site_security`:
    FAIL2BAN_FILTER_NAME = "wpfy-wordpress"
    fail2ban_available() -> bool
    fail2ban_filter_path() -> Path
    fail2ban_jail_path() -> Path
    set_fail2ban(domain, enabled) -> SecurityResult
    access_log_path(domain) -> Path
    `_DEFAULT_SECURITY["fail2ban"] = False`

  The access log lives under the site's own directory and is bind-mounted into
  its nginx container. Its format must be nginx's `combined` or a superset, so
  the first field is the client address — that is what B4's sample lines assume
  and what every published fail2ban WordPress filter expects.

  `fail2ban_available()` is what B2 fakes. Detect the binary, not a package
  manager; `shutil.which("fail2ban-client")` is the obvious answer.
"""

from __future__ import annotations

import os
import re
import stat as stat_module
from pathlib import Path

import pytest

DOMAIN_A = "f2b-one.example"
DOMAIN_B = "f2b-two.example"
SITE_UID = 1813

# Lines in nginx `combined` format. The failures must match the generated
# filter; the success must not, or every visitor gets banned.
#
# AMENDED after 7e landed. The original FAILED_LOGIN_LINES carried
#     '... "POST /xmlrpc.php HTTP/1.1" 403 ...'
# and that line was wrong: WordPress answers a failed XML-RPC authentication
# with HTTP **200** and an XML `<fault>` body — `xmlrpc.php` never calls
# `status_header(401)`. The gate asserted a status real WordPress does not
# emit, the implementation matched the gate faithfully, and the result was a
# filter rule that cannot fire on any production log. That is the exact silent
# failure this gate file exists to prevent, introduced by the gate itself.
#
# The line is removed rather than corrected to `200`. A status-independent
# `POST /xmlrpc.php` rule fires on ordinary Jetpack and mobile-app traffic,
# which easily exceeds maxretry 5 inside findtime 10m — an availability
# regression caused by the security feature, the same class as banning Traefik.
# `wp-login.php` is the brute-force surface wpfy actually defends; the answer
# for xmlrpc is to block the endpoint, not to ban its users.
#
# The 200-status xmlrpc line therefore moves to SUCCESS_LINES, where it pins
# that no later widening of the filter can ban a legitimate XML-RPC client.
FAILED_LOGIN_LINES = (
    '203.0.113.9 - - [28/Jul/2026:01:00:00 +0000] "POST /wp-login.php HTTP/1.1" 200 4021 "-" "curl/8.0"',
    '203.0.113.9 - - [28/Jul/2026:01:00:01 +0000] "POST /wp-login.php HTTP/1.1" 401 12 "-" "python-requests/2.0"',
)
SUCCESS_LINES = (
    '203.0.113.9 - - [28/Jul/2026:01:00:03 +0000] "GET / HTTP/1.1" 200 5120 "-" "Mozilla/5.0"',
    '203.0.113.9 - - [28/Jul/2026:01:00:04 +0000] "GET /wp-admin/ HTTP/1.1" 302 0 "-" "Mozilla/5.0"',
    '203.0.113.9 - - [28/Jul/2026:01:00:05 +0000] "GET /wp-includes/js/x.js HTTP/1.1" 200 900 "-" "Mozilla/5.0"',
    '198.51.100.4 - - [28/Jul/2026:01:00:06 +0000] "POST /xmlrpc.php HTTP/1.1" 200 412 "-" "Jetpack by WordPress.com"',
)

HOSTILE_VALUES = (
    "true\n[evil]\nenabled = true",
    "1; rm -rf /",
    "$(id)",
    "`id`",
    "../../etc/passwd",
    "\n[DEFAULT]\nbanaction = iptables-allports",
)

_GATE_ENV = (
    "WPFY_INSTALL_ROOT", "WPFY_CONFIG_DIR", "WPFY_STATE_DIR", "WPFY_LOG_DIR",
    "WPFY_SKIP_RUNTIME", "WPFY_SKIP_CHOWN", "WPFY_TEST_TRAEFIK_NETWORK_CIDRS",
)
_PATH_FIELDS = ("install_root", "config_dir", "state_dir", "log_dir")


def _seed_site(paths, domain: str, *, uid: int) -> Path:
    site = Path(paths.sites_dir) / domain
    (site / "nginx" / "extra").mkdir(parents=True, exist_ok=True)
    (site / "app").mkdir(parents=True, exist_ok=True)
    (site / ".env").write_text(
        f"DOMAIN={domain}\nSITE_FLAVOR=wp\n"
        f"COMPOSE_PROJECT_NAME={domain.replace('.', '-')}\n"
        "APP_ROOT=/var/www/html\nPHP_VERSION=8.4\n"
        f"SITE_UID={uid}\nLETSENCRYPT_MODE=disabled\n"
        "PAGE_CACHE=none\nREDIS_ENABLED=0\n"
        "DB_NAME=f2b\nDB_USER=f2b\nDB_PASSWORD=PH7E-db-secret\n",
        encoding="utf-8",
    )
    (site / "compose.yaml").write_text("services: {}\n", encoding="utf-8")
    (site / "nginx" / "default.conf").write_text("server {\n    listen 8080;\n}\n", encoding="utf-8")
    (site / "nginx" / "cache-path.conf").write_text("", encoding="utf-8")
    return site


@pytest.fixture
def gate_home(tmp_path):
    """Isolated home with two seeded WordPress sites.

    Paths are redirected by mutating the frozen `settings.PATHS` singleton in
    place. `importlib.reload` is deliberately avoided: it reuses a module's
    __dict__, so symbols captured at import time by other test modules keep
    pointing at the old class while the module starts producing the new one,
    silently breaking unrelated tests with no possible teardown.
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
        "WPFY_SKIP_RUNTIME": "1",
        "WPFY_SKIP_CHOWN": "1",
        "WPFY_TEST_TRAEFIK_NETWORK_CIDRS": "172.31.242.0/24",
    })
    for field in _PATH_FIELDS:
        object.__setattr__(paths, field, os.environ[f"WPFY_{field.upper()}"])
    for directory in (paths.state_dir, paths.log_dir, paths.config_dir):
        Path(directory).mkdir(parents=True, exist_ok=True)

    wpfy.registry._REGISTRY = None
    _seed_site(paths, DOMAIN_A, uid=SITE_UID)
    _seed_site(paths, DOMAIN_B, uid=SITE_UID + 1)
    try:
        yield paths
    finally:
        for field, value in previous_paths.items():
            object.__setattr__(paths, field, value)
        wpfy.registry._REGISTRY = previous_registry
        for name, value in previous_env.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value


def _enable(domain=DOMAIN_A, enabled=True):
    import wpfy.site_security as site_security

    return site_security.set_fail2ban(domain, enabled)


def _filter_text() -> str:
    import wpfy.site_security as site_security

    path = site_security.fail2ban_filter_path()
    return path.read_text(encoding="utf-8") if path.exists() else ""


def _jail_text() -> str:
    import wpfy.site_security as site_security

    path = site_security.fail2ban_jail_path()
    return path.read_text(encoding="utf-8") if path.exists() else ""


def _nginx_source() -> str:
    import wpfy.site_layout as site_layout

    return Path(site_layout.__file__).read_text(encoding="utf-8")


def _force_available(monkeypatch, available: bool) -> None:
    import wpfy.site_security as site_security

    monkeypatch.setattr(site_security, "fail2ban_available", lambda: available)


# ---------------------------------------------------------------------------
# L1-L4 — there has to be a log before anything can read one
# ---------------------------------------------------------------------------

def test_gate_each_site_writes_its_own_host_visible_access_log(gate_home):
    """L1: today every site logs to container stdout and nothing reaches the
    host, so fail2ban has nothing to read. A shared log would also let one
    tenant's traffic ban another's visitors.
    """
    import wpfy.site_security as site_security

    log_a = site_security.access_log_path(DOMAIN_A)
    log_b = site_security.access_log_path(DOMAIN_B)
    assert log_a != log_b, f"both sites share one access log at {log_a}"

    site_a = Path(gate_home.sites_dir) / DOMAIN_A
    assert site_a.resolve() in log_a.resolve().parents, (
        f"the access log {log_a} does not live under the site it belongs to"
    )
    source = _nginx_source()
    assert "access_log" in source and str("wpfy-access") in source or "access_log /var/log" in source, (
        "the generated nginx config never directs an access log to a mounted path"
    )


def test_gate_the_log_records_the_real_client(gate_home):
    """L2: nginx sits behind Traefik. Without `real_ip` every line records the
    edge proxy, and a jail reading that log bans Traefik — taking every site on
    the box offline at once. This is not a degraded feature, it is an outage.
    """
    import wpfy.site_security as site_security
    import wpfy.traefik as traefik

    result = site_security.render_security(DOMAIN_A)
    assert result.exit_code in (0, 3)
    snippet = (Path(gate_home.sites_dir) / DOMAIN_A / "nginx" / "extra"
               / site_security.SECURITY_SNIPPET)
    text = snippet.read_text(encoding="utf-8") if snippet.exists() else ""
    combined = text + _nginx_source()

    assert "set_real_ip_from" in combined, (
        "no real-ip trust is configured, so every log line records Traefik and "
        "a fail2ban jail would ban the edge proxy"
    )
    assert "real_ip_header" in combined
    for cidr in traefik.traefik_network_cidrs():
        assert cidr in combined, f"the edge network {cidr} is not trusted for real-ip"


def test_gate_the_access_log_is_rotated(gate_home):
    """L3: a busy site writes gigabytes. An unbounded log on the host is a
    disk-fill outage that takes every site down, which is a worse failure than
    the brute force it was added to observe.
    """
    source = _nginx_source() + _filter_text() + _jail_text()
    import wpfy.site_security as site_security

    module = Path(site_security.__file__).read_text(encoding="utf-8")
    combined = (source + module).lower()
    assert "logrotate" in combined or "rotate" in combined, (
        "nothing rotates the access log this phase introduces"
    )


def test_gate_the_access_log_is_not_world_readable(gate_home, monkeypatch):
    """L4: access logs carry client addresses, request paths, and query strings.
    On a shared host that is other people's traffic.
    """
    import wpfy.site_security as site_security

    _force_available(monkeypatch, True)
    assert _enable().exit_code == 0
    log = site_security.access_log_path(DOMAIN_A)
    if not log.exists():
        log.parent.mkdir(parents=True, exist_ok=True)
        log.touch()
    mode = stat_module.S_IMODE(log.stat().st_mode)
    assert not mode & 0o004, f"the access log is world-readable ({oct(mode)})"


# ---------------------------------------------------------------------------
# B1-B9 — the jail
# ---------------------------------------------------------------------------

def test_gate_fail2ban_is_opt_in(gate_home):
    """B1: fail2ban is a host package and banning is a host-level action. This
    project does not mutate the host without being asked.
    """
    import wpfy.site_security as site_security

    assert site_security._DEFAULT_SECURITY.get("fail2ban") is False, (
        "fail2ban integration is on by default"
    )
    assert site_security.load_security(DOMAIN_A).get("fail2ban") is False
    assert not _jail_text(), "an untouched site already has a jail installed"


def test_gate_enabling_refuses_cleanly_without_fail2ban(gate_home, monkeypatch):
    """B2: writing a jail for a daemon that is not installed produces a config
    an operator believes is protecting them. Refuse, say why, and leave nothing
    behind — a half-written jail is worse than none.
    """
    import wpfy.site_security as site_security

    _force_available(monkeypatch, False)
    result = _enable()
    assert result.exit_code != 0, "enabling succeeded although fail2ban is absent"
    assert "fail2ban" in result.message.lower(), f"the refusal does not say why: {result.message}"
    assert not _jail_text(), "a jail was written although fail2ban is absent"
    assert not _filter_text(), "a filter was written although fail2ban is absent"
    assert site_security.load_security(DOMAIN_A).get("fail2ban") is False, (
        "the stored config claims fail2ban is enabled although it was refused"
    )


def test_gate_enabling_writes_a_filter_and_a_jail(gate_home, monkeypatch):
    """B3: anti-vacuity for B1 and B2, which both pass against a `set_fail2ban`
    that refuses unconditionally or does not exist."""
    _force_available(monkeypatch, True)
    result = _enable()
    assert result.exit_code == 0, f"enabling failed: {result.message}"
    assert _filter_text(), "no fail2ban filter was written"
    assert _jail_text(), "no fail2ban jail was written"


def test_gate_the_filter_matches_what_nginx_actually_writes(gate_home, monkeypatch):
    """B4: the gate that separates a working jail from a decorative one.

    fail2ban's entire value is the agreement between a log line nginx writes and
    a regex fail2ban reads. Everything else in this project fails loudly — a bad
    compose file will not start, a bad nginx directive will not reload. A filter
    that matches nothing fails *silently*: it looks installed, reports zero bans
    forever, and is indistinguishable from a quiet week.

    So the regex is compiled here and run against real `combined`-format lines.
    `<HOST>` is fail2ban's own placeholder and is substituted with an address
    pattern the way fail2ban would.
    """
    _force_available(monkeypatch, True)
    assert _enable().exit_code == 0
    text = _filter_text()

    patterns = re.findall(r"^\s*(?:failregex\s*=|\s+)(.*<HOST>.*)$", text, re.MULTILINE)
    assert patterns, f"the filter declares no failregex containing <HOST>:\n{text}"

    compiled = []
    for pattern in patterns:
        source = pattern.strip().replace("<HOST>", r"(?P<host>[0-9a-fA-F:.]+)")
        try:
            compiled.append(re.compile(source))
        except re.error as exc:
            pytest.fail(f"failregex does not compile: {source!r} ({exc})")

    for line in FAILED_LOGIN_LINES:
        assert any(rx.search(line) for rx in compiled), (
            "the filter matches none of the abusive lines nginx writes, so the "
            f"jail can never ban anyone:\n  line:    {line}\n  patterns: {patterns}"
        )
    for line in SUCCESS_LINES:
        assert not any(rx.search(line) for rx in compiled), (
            "the filter matches ordinary successful traffic, so it will ban real "
            f"visitors:\n  line:    {line}\n  patterns: {patterns}"
        )


def test_gate_the_jail_reads_the_log_the_site_writes(gate_home, monkeypatch):
    """B5: a jail pointed at a path nothing writes is the same silent failure as
    B4, reached by a different route.
    """
    import wpfy.site_security as site_security

    _force_available(monkeypatch, True)
    assert _enable().exit_code == 0
    jail = _jail_text()
    log = str(site_security.access_log_path(DOMAIN_A))

    assert log in jail, f"the jail does not reference {log}:\n{jail}"
    assert site_security.FAIL2BAN_FILTER_NAME in jail, (
        f"the jail does not reference the filter this phase installs:\n{jail}"
    )
    assert "enabled" in jail and "true" in jail.lower()


def test_gate_the_ban_lands_in_the_docker_user_chain(gate_home, monkeypatch):
    """B6: traffic to a published container port is DNAT'd and traverses
    FORWARD, not INPUT. The stock iptables action therefore bans nothing at all
    on a Docker host while reporting success — the jail fires, the counter
    increments, and the attacker keeps connecting.
    """
    _force_available(monkeypatch, True)
    assert _enable().exit_code == 0
    combined = (_jail_text() + _filter_text())

    assert "DOCKER-USER" in combined, (
        "the ban action does not target DOCKER-USER, so bans on this Docker "
        f"host will not actually block anything:\n{combined}"
    )
    assert not re.search(r"\bchain\s*=\s*INPUT\b", combined), (
        "the ban action targets INPUT, which container-destined traffic bypasses"
    )


def test_gate_enabling_twice_is_enabling_once(gate_home, monkeypatch):
    """B7: the standing idempotency rule."""
    _force_available(monkeypatch, True)
    assert _enable().exit_code == 0
    first_filter, first_jail = _filter_text(), _jail_text()

    assert _enable().exit_code == 0
    assert _filter_text() == first_filter, "a repeat enable rewrote the filter"
    assert _jail_text() == first_jail, "a repeat enable rewrote the jail"


def test_gate_disabling_removes_everything_and_repeats_safely(gate_home, monkeypatch):
    """B8: a jail that outlives its "off" switch keeps banning, and the operator
    who turned it off has no reason to look for it.
    """
    import wpfy.site_security as site_security

    _force_available(monkeypatch, True)
    assert _enable().exit_code == 0
    assert _jail_text()

    assert _enable(enabled=False).exit_code == 0
    assert DOMAIN_A not in _jail_text(), (
        f"disabling left this site's jail in place:\n{_jail_text()}"
    )
    assert site_security.load_security(DOMAIN_A).get("fail2ban") is False
    assert _enable(enabled=False).exit_code == 0, "a second disable failed"


def test_gate_nothing_attacker_influenced_reaches_the_jail(gate_home, monkeypatch):
    """B9: `security.json` is a file a restore or a hand edit can put anything
    into, and it is rendered into a config a root daemon reads. Every other
    value in that file is validated on read for exactly this reason.
    """
    import wpfy.site_security as site_security

    _force_available(monkeypatch, True)
    assert _enable().exit_code == 0
    assert _jail_text(), "the feature does not render, so the assertions below are vacuous"

    for value in HOSTILE_VALUES:
        config = dict(site_security._DEFAULT_SECURITY)
        config["fail2ban"] = value
        site_security.save_security(DOMAIN_A, config)
        site_security.render_security(DOMAIN_A)
        combined = _jail_text() + _filter_text()
        for marker in ("[evil]", "rm -rf", "$(id)", "`id`", "iptables-allports", "/etc/passwd"):
            assert marker not in combined, (
                f"{value!r} injected {marker!r} into the generated fail2ban config"
            )


# ---------------------------------------------------------------------------
# H1-H5 — hardening, and the inode footgun
# ---------------------------------------------------------------------------

def test_gate_wordpress_installer_endpoints_are_refused(gate_home):
    """H1: `install.php` on a site whose database is momentarily reachable is a
    complete takeover, and `upgrade.php` is reachable without a session.
    """
    source = _nginx_source()
    for target in ("install.php", "upgrade.php"):
        assert target in source, f"{target} is not handled by the generated nginx config"
        window = source[max(0, source.find(target) - 400): source.find(target) + 400]
        assert re.search(r"return\s+40[34]|deny all", window), (
            f"{target} appears but is not refused:\n{window}"
        )


def test_gate_backup_plugin_directories_are_refused(gate_home):
    """H2: UpdraftPlus and Sucuri write archives under `wp-content`, served by
    the same nginx as everything else. A downloadable backup is the database,
    the salts, and every uploaded file in one request.
    """
    source = _nginx_source()
    for marker in ("updraft", "sucuri"):
        assert marker in source.lower(), (
            f"backup-plugin directory {marker!r} is not blocked; its archives are "
            "downloadable by anyone who guesses the path"
        )


def test_gate_the_deprecated_xss_filter_is_disabled(gate_home):
    """H3: `X-XSS-Protection` is deprecated, and leaving it unset lets legacy
    browsers apply a filter that has its own documented attack surface. The
    modern guidance is to send `0` explicitly rather than omit the header.
    """
    source = _nginx_source()
    assert "X-XSS-Protection" in source, "the deprecated XSS filter is not addressed at all"
    window = source[source.find("X-XSS-Protection") - 100: source.find("X-XSS-Protection") + 200]
    assert '"0"' in window or "'0'" in window or " 0 " in window, (
        f"X-XSS-Protection is set to something other than 0:\n{window}"
    )


def test_gate_ordinary_wordpress_paths_still_reach_php(gate_home):
    """H4: anti-vacuity for H1-H3. Every hardening gate above is satisfied by a
    config that refuses everything, which is also a broken site.
    """
    source = _nginx_source()
    assert "fastcgi_pass" in source, "nothing reaches PHP any more"
    assert "try_files $uri $uri/ /index.php?$args;" in source, (
        "the WordPress front controller rewrite is gone"
    )
    for path in ("wp-admin", "wp-includes", "wp-content"):
        blocked_everywhere = re.search(
            rf"location\s*\^?~\*?\s*/?{path}/?\s*\{{\s*(deny all|return 40)", source)
        assert not blocked_everywhere, (
            f"/{path}/ is refused wholesale, which breaks the site rather than hardening it"
        )


def test_gate_individually_mounted_files_keep_their_inode(gate_home):
    """H5: the footgun this project has already been bitten by.

    A generated file that is bind-mounted **individually** — not as part of a
    directory — must be written in place. `os.replace` allocates a new inode;
    the mount keeps resolving the old one, so the container reads stale content
    forever while the file on disk looks correct. Nothing about this is visible
    in a diff, in a test that reads the file, or in the container's logs.
    """
    import wpfy.site_security as site_security

    site = Path(gate_home.sites_dir) / DOMAIN_A
    mounted = [
        site / "nginx" / "cache-path.conf",
        site / "nginx" / site_security.RATELIMIT_SNIPPET,
    ]
    for path in mounted:
        if not path.exists():
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("", encoding="utf-8")

    before = {path: path.stat().st_ino for path in mounted}
    site_security.set_login_rate_limit(DOMAIN_A, True)
    site_security.render_security(DOMAIN_A)

    for path, inode in before.items():
        if not path.exists():
            continue
        assert path.stat().st_ino == inode, (
            f"{path.name} was replaced rather than rewritten in place; its bind "
            "mount now points at an orphaned inode and the container will read "
            "stale content until it is recreated"
        )
