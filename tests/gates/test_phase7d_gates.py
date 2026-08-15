"""GATE TESTS — Phase 7d (login rate limiting and cooldown).

These tests are the security and correctness contract for Phase 7d. They were
written before the implementation and encode decisions, not implementation
details, so a gate failing usually means the product regressed rather than that
the gate is out of date.

They are editable, and were immutable until 2026-08-15. Change one only when
the decision it pins has genuinely changed, never to make a red test green:
say in the commit which decision moved and why, and keep the gate asserting the
new one. A gate deleted or weakened to pass takes its invariant with it.

This file is deliberately self-contained: it depends only on the stdlib and the
`wpfy` package, never on other test modules or shared fixtures.

Two surfaces, one concern:

    **The panel login.** Phase 7a gave it a per-*account* lockout, which stops
    someone guessing at one password and does nothing at all about volume. Every
    `POST /api/auth/login` runs scrypt by design — that is the point of scrypt —
    so an unauthenticated flood is a CPU exhaustion primitive that needs no
    valid username to work. 7a even made this worse in one specific way for the
    right reason: failures are recorded only for accounts that exist, so
    guessing at names that do not exist is *untracked* by design. Something has
    to bound the request rate itself, and it has to be per-client.

    **The WordPress login.** `wp-login.php` is the most brute-forced endpoint on
    the public internet. wpfy blocks `xmlrpc.php` with a 404 and leaves
    `wp-login.php` completely open. There is no rate limiting anywhere in this
    codebase today — this phase adds the first.

What this phase can get wrong that nothing else catches:

    1. **A rate limit on `wp-login.php` can disclose PHP source.** The generated
       server block handles PHP with `location ~* \\.php$`. An exact-match
       `location = /wp-login.php` added to carry `limit_req` **wins over that
       regex** — nginx prefers `=` over every regex match. If the new block does
       not repeat the FastCGI directives, nginx falls back to serving the file
       from `root /var/www/html` as a static asset: the login page stops working
       and the raw PHP is handed to the client. The feature meant to protect the
       login instead publishes the source of it. That is gate W3, and it is the
       one gate a plausible wrong implementation fails.
    2. **`limit_req zone=X` with no matching `limit_req_zone X` is a hard nginx
       startup failure.** `limit_req_zone` is an `http`-context directive and the
       per-site snippet is included inside `server`, so the two live in
       different files. Get the coupling wrong and enabling a security feature
       takes the site offline — worse than the attack it prevents.
    3. **A shared zone breaks site isolation.** One `limit_req_zone` used by
       every site means one site's traffic throttles its neighbours, which is a
       direct violation of the project's isolation rule and an easy denial of
       service against a co-tenant.
    4. **A throttle keyed on a spoofable header is not a throttle.** If the panel
       keys its per-client counter on `X-Forwarded-For`, every attacker gets a
       fresh bucket per request by varying one header, and the whole control is
       decorative while looking correct in every test that does not try it.

Invariants locked here:
  P1   Repeated failed panel logins from one client are throttled, whatever
       usernames are used — including usernames that do not exist.
  P2   The panel throttle is a cooldown: it expires rather than banning forever.
  P3   Anti-vacuity for P1/P2: valid credentials work before the threshold, and
       again after the cooldown.
  P4   The panel throttle key cannot be moved by a request header.
  P5   The panel throttle is always on, not conditional on exposure.
  P6   A throttled panel login answers 429 and does not run the KDF.
  P7   The panel throttle records an event.
  W1   WordPress login rate limiting is opt-in and off by default.
  W2   Enabled, it emits a `limit_req` for `wp-login.php`.
  W3   Enabled, `wp-login.php` is still executed by PHP and never served as a
       static file.
  W4   The zone is per-site, never shared between sites.
  W5   Every referenced zone is defined, so nginx still starts.
  W6   The zone's memory is bounded.
  W7   Rejections answer 429, not 503.
  W8   Disabling removes every directive it added.
  W9   Enabling twice is enabling once.
  W10  The generated config cannot be injected through the stored config.
  W11  Anti-vacuity for W8: the rest of the hardening survives being enabled.
  W12  `xmlrpc.php` stays blocked.
  W13  The limit keys on the real client, not on the edge proxy in front of it.
  W14  The zone key is the binary client address and nothing request-controlled.
  W15  Concurrent connections are capped, with every zone defined.

Contract pinned by these gates (the actor must match these names exactly):

  `wpfy.panel_auth`:
    MAX_CLIENT_FAILURES          int, per-client failure threshold
    CLIENT_COOLDOWN_SECONDS      float/int, read at use time
    login(username, password, totp=None, *, client=None)
        `client` is the peer address the panel took from the socket. A throttled
        client is refused before the KDF runs. `login()` keeps returning None on
        refusal; the HTTP layer maps a throttled client to 429.
    client_throttled(client) -> bool
    reset_state()                also clears client throttle state

  `wpfy.site_security`:
    RATELIMIT_SNIPPET = "wpfy-ratelimit.conf"     http-context zone file
    LOGIN_RATE_LIMIT_RATE                         e.g. "5r/m"
    LOGIN_RATE_LIMIT_BURST                        int
    LOGIN_RATE_LIMIT_ZONE_SIZE                    e.g. "1m"
    login_zone_name(domain) -> str                per-site, deterministic
    set_login_rate_limit(domain, enabled) -> SecurityResult
    `_DEFAULT_SECURITY["login_rate_limit"] = False`

  The zone file is rendered into the site's `nginx/` directory and mounted at
  `/etc/nginx/conf.d/00-wpfy-ratelimit.conf`, alongside the existing
  `00-wpfy-cache-path.conf`. It is mounted as an individual file, so it must be
  written **in place** — never through `os.replace`, which breaks the bind-mount
  inode. `site_security._safe_write_in_place` already exists for this.
"""

from __future__ import annotations

import http.client
import json
import os
import re
import threading
import time
from pathlib import Path

import pytest

GATE_TOKEN = "phase7d-run-token"
ADMIN_USER = "gate-rl-admin"
ADMIN_PASSWORD = "PH7D-admin-pw-4a91cc"
DOMAIN_A = "rl-one.example"
DOMAIN_B = "rl-two.example"
SITE_UID = 1809

_GATE_ENV = (
    "WPFY_INSTALL_ROOT",
    "WPFY_CONFIG_DIR",
    "WPFY_STATE_DIR",
    "WPFY_LOG_DIR",
    "WPFY_SKIP_RUNTIME",
    "WPFY_SKIP_WORDPRESS_DOWNLOAD",
    "WPFY_SKIP_CHOWN",
    "WPFY_TEST_TRAEFIK_NETWORK_CIDRS",
)

_PATH_FIELDS = ("install_root", "config_dir", "state_dir", "log_dir")

# Values that must not be able to close a directive and start a new one.
HOSTILE_RATE_VALUES = (
    "5r/m;\nlimit_req_zone $binary_remote_addr zone=evil:10m rate=1000r/s",
    "5r/m; deny all",
    "5r/m}\nserver {",
    "5r/m #",
    "$binary_remote_addr",
    "../../etc/passwd",
    "",
    "-1r/s",
)


class Response:
    def __init__(self, status: int, body: bytes):
        self.status = status
        self.body = body

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", "replace")


def _seed_site(paths, domain: str, *, uid: int) -> Path:
    site = Path(paths.sites_dir) / domain
    (site / "nginx" / "extra").mkdir(parents=True, exist_ok=True)
    (site / "php").mkdir(parents=True, exist_ok=True)
    (site / "app").mkdir(parents=True, exist_ok=True)
    (site / ".env").write_text(
        f"DOMAIN={domain}\nSITE_FLAVOR=wp\n"
        f"COMPOSE_PROJECT_NAME={domain.replace('.', '-')}\n"
        "APP_ROOT=/var/www/html\nPHP_VERSION=8.4\n"
        f"SITE_UID={uid}\nLETSENCRYPT_MODE=disabled\n"
        "PAGE_CACHE=none\nREDIS_ENABLED=0\n"
        "DB_NAME=rldb\nDB_USER=rldb\nDB_PASSWORD=PH7D-db-secret\n",
        encoding="utf-8",
    )
    (site / "compose.yaml").write_text("services: {}\n", encoding="utf-8")
    (site / "nginx" / "default.conf").write_text("server {\n    listen 8080;\n}\n", encoding="utf-8")
    (site / "nginx" / "extra" / "custom.conf").write_text("", encoding="utf-8")
    (site / "nginx" / "cache-path.conf").write_text("", encoding="utf-8")
    return site


@pytest.fixture
def gate_home(tmp_path):
    """Isolated home, two seeded sites, and a live loopback panel.

    Paths are redirected by mutating the frozen `settings.PATHS` singleton in
    place. `importlib.reload` is deliberately avoided: it reuses a module's
    __dict__, so symbols captured at import time by other test modules keep
    pointing at the old class while the module starts producing the new one,
    silently breaking unrelated tests with no possible teardown.

    Two sites exist because W4 — one site's throttle must not touch another's —
    cannot be stated with one.
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
        "WPFY_SKIP_WORDPRESS_DOWNLOAD": "1",
        "WPFY_SKIP_CHOWN": "1",
        "WPFY_TEST_TRAEFIK_NETWORK_CIDRS": "172.31.241.0/24",
    })
    for field in _PATH_FIELDS:
        object.__setattr__(paths, field, os.environ[f"WPFY_{field.upper()}"])
    for directory in (paths.state_dir, paths.log_dir, paths.config_dir):
        Path(directory).mkdir(parents=True, exist_ok=True)

    wpfy.registry._REGISTRY = None
    _seed_site(paths, DOMAIN_A, uid=SITE_UID)
    _seed_site(paths, DOMAIN_B, uid=SITE_UID + 1)

    import wpfy.panel as panel
    import wpfy.panel_auth as panel_auth

    panel_auth.reset_state()
    config = panel.PanelConfig(host="127.0.0.1", port=0, token=GATE_TOKEN)
    server = panel.make_panel_server(config)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield type("Home", (), {
            "host": "127.0.0.1", "port": server.server_address[1],
            "paths": paths, "root": tmp_path,
        })
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        panel_auth.reset_state()
        for field, value in previous_paths.items():
            object.__setattr__(paths, field, value)
        wpfy.registry._REGISTRY = previous_registry
        for name, value in previous_env.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value


def _login_http(home, username, password, headers=None) -> Response:
    connection = http.client.HTTPConnection(home.host, home.port, timeout=30)
    try:
        sent = {"Content-Type": "application/json", **(headers or {})}
        payload = json.dumps({"username": username, "password": password}).encode("utf-8")
        connection.request("POST", "/api/auth/login", body=payload, headers=sent)
        response = connection.getresponse()
        return Response(response.status, response.read())
    finally:
        connection.close()


def _seed_admin():
    import wpfy.panel_auth as panel_auth

    panel_auth.add_user(ADMIN_USER, ADMIN_PASSWORD, role=panel_auth.ROLE_ADMIN)


def _snippet_text(domain: str) -> str:
    import wpfy.settings as settings
    import wpfy.site_security as site_security

    path = (Path(settings.PATHS.sites_dir) / domain / "nginx" / "extra"
            / site_security.SECURITY_SNIPPET)
    return path.read_text(encoding="utf-8") if path.exists() else ""


def _zone_text(domain: str) -> str:
    import wpfy.settings as settings
    import wpfy.site_security as site_security

    path = (Path(settings.PATHS.sites_dir) / domain / "nginx"
            / site_security.RATELIMIT_SNIPPET)
    return path.read_text(encoding="utf-8") if path.exists() else ""


# ---------------------------------------------------------------------------
# P1-P7 — the panel login
# ---------------------------------------------------------------------------

def test_gate_panel_throttles_a_client_across_usernames(gate_home):
    """P1: 7a's counter is per account and — deliberately — records nothing at
    all for usernames that do not exist, which is exactly what a spray does.
    Without a per-client bound, unlimited scrypt runs are free.
    """
    import wpfy.panel_auth as panel_auth

    _seed_admin()
    assert panel_auth.MAX_CLIENT_FAILURES <= 50, (
        f"MAX_CLIENT_FAILURES is {panel_auth.MAX_CLIENT_FAILURES}, too high to bound a flood"
    )

    client = "203.0.113.42"
    for index in range(panel_auth.MAX_CLIENT_FAILURES):
        panel_auth.login(f"does-not-exist-{index}", "wrong", client=client)

    assert panel_auth.client_throttled(client) is True, (
        "a client that sprayed distinct unknown usernames is not throttled, so "
        "the per-account counter is the only bound and it never fires"
    )
    assert panel_auth.client_throttled("198.51.100.7") is False, (
        "throttling one client throttled every client"
    )


def test_gate_panel_throttle_is_a_cooldown_not_a_ban(gate_home, monkeypatch):
    """P2: a permanent block turns a forgotten password into a support ticket,
    and turns one spoofable request into a denial of service against the
    operator's own address.
    """
    import wpfy.panel_auth as panel_auth

    _seed_admin()
    monkeypatch.setattr(panel_auth, "CLIENT_COOLDOWN_SECONDS", 0.5)
    client = "203.0.113.43"
    for index in range(panel_auth.MAX_CLIENT_FAILURES):
        panel_auth.login(f"nobody-{index}", "wrong", client=client)
    assert panel_auth.client_throttled(client) is True

    time.sleep(0.8)
    assert panel_auth.client_throttled(client) is False, (
        "the client throttle never expires, so it is a ban rather than a cooldown"
    )


def test_gate_valid_credentials_still_work(gate_home, monkeypatch):
    """P3: anti-vacuity. Every gate above passes against a panel that refuses
    every login from everyone, forever.
    """
    import wpfy.panel_auth as panel_auth

    _seed_admin()
    monkeypatch.setattr(panel_auth, "CLIENT_COOLDOWN_SECONDS", 0.5)

    assert panel_auth.login(ADMIN_USER, ADMIN_PASSWORD, client="203.0.113.44") is not None, (
        "a correct password was refused before any throttling could apply"
    )

    client = "203.0.113.45"
    for index in range(panel_auth.MAX_CLIENT_FAILURES):
        panel_auth.login(f"nobody-{index}", "wrong", client=client)
    assert panel_auth.login(ADMIN_USER, ADMIN_PASSWORD, client=client) is None

    time.sleep(0.8)
    assert panel_auth.login(ADMIN_USER, ADMIN_PASSWORD, client=client) is not None, (
        "a correct password is still refused after the cooldown expired"
    )


def test_gate_panel_throttle_key_cannot_be_moved_by_a_header(gate_home):
    """P4: keying on `X-Forwarded-For` gives every attacker a fresh bucket per
    request by varying one header, while looking correct in any test that does
    not vary it. The panel is loopback-only or behind wpfy's own edge, so the
    socket peer is the only trustworthy source.
    """
    import wpfy.panel_auth as panel_auth

    _seed_admin()
    attempts = panel_auth.MAX_CLIENT_FAILURES + 2
    for index in range(attempts):
        _login_http(gate_home, f"nobody-{index}", "wrong", headers={
            "X-Forwarded-For": f"203.0.113.{index % 250}",
            "X-Real-IP": f"198.51.100.{index % 250}",
            "Forwarded": f"for=192.0.2.{index % 250}",
        })

    response = _login_http(gate_home, ADMIN_USER, ADMIN_PASSWORD, headers={
        "X-Forwarded-For": "203.0.113.251",
    })
    assert response.status == 429, (
        f"varying forwarding headers escaped the throttle: got {response.status}, "
        "so the counter is keyed on attacker-controlled input"
    )


def test_gate_panel_throttle_is_always_on(gate_home):
    """P5: the panel is reachable over an SSH tunnel whether or not it is
    exposed through Traefik, and 7b's edge rate limit only covers the exposed
    path. A throttle that depends on exposure is absent exactly when someone has
    chosen not to publish but still has a tunnel open.
    """
    import wpfy.panel_exposure as panel_exposure
    import wpfy.panel_auth as panel_auth

    _seed_admin()
    assert panel_exposure.exposure_status().get("exposed") is False

    client = "203.0.113.46"
    for index in range(panel_auth.MAX_CLIENT_FAILURES):
        panel_auth.login(f"nobody-{index}", "wrong", client=client)
    assert panel_auth.client_throttled(client) is True, (
        "the client throttle only engages once the panel is exposed"
    )


def test_gate_throttled_login_answers_429_without_running_the_kdf(gate_home, monkeypatch):
    """P6: 429 is the honest status and the one a client can act on. Skipping the
    KDF is the entire point — if a throttled request still pays for scrypt, the
    throttle does not defend the CPU it was added to defend.
    """
    import hashlib

    import wpfy.panel_auth as panel_auth

    _seed_admin()
    attempts = panel_auth.MAX_CLIENT_FAILURES + 1
    for index in range(attempts):
        _login_http(gate_home, f"nobody-{index}", "wrong")

    calls = []
    real = hashlib.scrypt
    monkeypatch.setattr(panel_auth.hashlib, "scrypt",
                        lambda *a, **k: (calls.append(1), real(*a, **k))[1])

    response = _login_http(gate_home, ADMIN_USER, ADMIN_PASSWORD)
    assert response.status == 429, f"a throttled login did not answer 429: {response.status}"
    assert not calls, (
        f"a throttled login still ran the KDF {len(calls)} time(s), so volume "
        "still costs the server exactly what it did before"
    )


def test_gate_panel_throttle_is_recorded(gate_home):
    """P7: a throttle nobody can see is an outage report rather than a signal.
    The panel already has an event log; this belongs in it.
    """
    import wpfy.events as events
    import wpfy.panel_auth as panel_auth

    _seed_admin()
    for index in range(panel_auth.MAX_CLIENT_FAILURES + 1):
        _login_http(gate_home, f"nobody-{index}", "wrong")

    recorded = json.dumps(events.list_events(limit=200)).lower()
    assert "throttl" in recorded or "rate" in recorded, (
        f"no throttle event was recorded; events seen: {recorded[:400]}"
    )
    assert "PH7D-admin-pw".lower() not in recorded, "the event log captured a password"


# ---------------------------------------------------------------------------
# W1-W12 — the WordPress login
# ---------------------------------------------------------------------------

def test_gate_wordpress_rate_limiting_is_opt_in(gate_home):
    """W1: opt-in, matching every other per-site security feature. A default-on
    throttle on a login page would surprise operators whose sites legitimately
    see bursts, and this project's convention is that security features are
    chosen rather than imposed.
    """
    import wpfy.site_security as site_security

    assert site_security._DEFAULT_SECURITY.get("login_rate_limit") is False, (
        "WordPress login rate limiting is on by default"
    )
    assert site_security.load_security(DOMAIN_A).get("login_rate_limit") is False
    assert "limit_req" not in _snippet_text(DOMAIN_A), (
        "an untouched site already carries a rate-limit directive"
    )


def test_gate_enabling_emits_a_login_rate_limit(gate_home):
    """W2: anti-vacuity for every W gate below — they all pass against a setter
    that stores a flag and renders nothing.
    """
    import wpfy.site_security as site_security

    result = site_security.set_login_rate_limit(DOMAIN_A, True)
    assert result.exit_code == 0, f"enabling failed: {result.message}"

    snippet = _snippet_text(DOMAIN_A)
    assert "limit_req" in snippet, f"no limit_req emitted:\n{snippet}"
    assert "wp-login.php" in snippet, f"the limit is not scoped to wp-login:\n{snippet}"
    assert site_security.load_security(DOMAIN_A).get("login_rate_limit") is True


def test_gate_wp_login_is_still_executed_by_php(gate_home):
    """W3: the gate that separates a working feature from a source disclosure.

    The generated server block runs PHP through `location ~* \\.php$`. An exact
    `location = /wp-login.php` added to carry `limit_req` beats that regex —
    nginx prefers `=` over every regex match. If the new block omits the FastCGI
    directives, nginx serves the file from `root /var/www/html` as a static
    asset: the login page stops working and the raw PHP source is returned to
    anyone who asks. A feature meant to protect the login would publish it.
    """
    import wpfy.site_security as site_security

    assert site_security.set_login_rate_limit(DOMAIN_A, True).exit_code == 0
    snippet = _snippet_text(DOMAIN_A)

    login_blocks = re.findall(
        r"location\s*=?\s*[^\{]*wp-login[^\{]*\{(.*?)\n\s*\}", snippet, re.DOTALL)
    assert login_blocks, f"no wp-login location block found:\n{snippet}"

    for block in login_blocks:
        handled = ("fastcgi_pass" in block) or ("proxy_pass" in block) or ("@" in block)
        assert handled, (
            "the wp-login location carries a rate limit but no PHP handler, so "
            f"nginx will serve wp-login.php as a static file:\n{block}"
        )
        if "fastcgi_pass" in block:
            assert "SCRIPT_FILENAME" in block or "fastcgi_params" in block, (
                f"the wp-login FastCGI block omits the parameters PHP needs:\n{block}"
            )


def test_gate_each_site_gets_its_own_zone(gate_home):
    """W4: a shared zone lets one site's traffic throttle its neighbours, which
    is the isolation rule broken in the most deniable way possible.
    """
    import wpfy.site_security as site_security

    assert site_security.set_login_rate_limit(DOMAIN_A, True).exit_code == 0
    assert site_security.set_login_rate_limit(DOMAIN_B, True).exit_code == 0

    zone_a = site_security.login_zone_name(DOMAIN_A)
    zone_b = site_security.login_zone_name(DOMAIN_B)
    assert zone_a != zone_b, f"both sites share the zone name {zone_a!r}"
    assert zone_a in _snippet_text(DOMAIN_A) and zone_a in _zone_text(DOMAIN_A)
    assert zone_a not in _snippet_text(DOMAIN_B), "site A's zone is referenced by site B"
    assert zone_b not in _snippet_text(DOMAIN_A), "site B's zone is referenced by site A"


def test_gate_every_referenced_zone_is_defined(gate_home):
    """W5: `limit_req zone=X` with no `limit_req_zone X` is a hard nginx startup
    failure. The two directives live in different files because one is
    http-context and the other server-context, so nothing but a test couples
    them. Enabling a security feature must not take the site offline.
    """
    import wpfy.site_security as site_security

    assert site_security.set_login_rate_limit(DOMAIN_A, True).exit_code == 0
    snippet = _snippet_text(DOMAIN_A)
    zones_file = _zone_text(DOMAIN_A)

    referenced = set(re.findall(r"limit_req\s+zone=([A-Za-z0-9_-]+)", snippet))
    defined = set(re.findall(r"limit_req_zone[^;]*zone=([A-Za-z0-9_-]+):", zones_file))
    assert referenced, f"no zone referenced although the limit is enabled:\n{snippet}"
    missing = referenced - defined
    assert not missing, (
        f"zones {sorted(missing)} are used but never defined; nginx refuses to "
        f"start with this config:\n--- server ---\n{snippet}\n--- http ---\n{zones_file}"
    )
    assert "limit_req_zone" not in snippet, (
        "limit_req_zone was emitted into the server-context snippet, where nginx "
        f"rejects it:\n{snippet}"
    )


def test_gate_zone_memory_is_bounded(gate_home):
    """W6: the zone is allocated per site. A generous size multiplied by every
    site on the box is real memory, and 1m already holds roughly 16k addresses.
    """
    import wpfy.site_security as site_security

    assert site_security.set_login_rate_limit(DOMAIN_A, True).exit_code == 0
    sizes = re.findall(r"zone=[A-Za-z0-9_-]+:(\d+)([kKmM])", _zone_text(DOMAIN_A))
    assert sizes, f"no zone size declared:\n{_zone_text(DOMAIN_A)}"
    for value, unit in sizes:
        megabytes = int(value) / 1024 if unit in "kK" else int(value)
        assert megabytes <= 8, f"the per-site zone reserves {value}{unit}, too much per site"


def test_gate_rejections_answer_429(gate_home):
    """W7: nginx's default for `limit_req` is 503, which reads as "this site is
    broken" to monitoring, to users, and to search crawlers that will happily
    de-index a site over it. 429 says what actually happened.
    """
    import wpfy.site_security as site_security

    assert site_security.set_login_rate_limit(DOMAIN_A, True).exit_code == 0
    text = _snippet_text(DOMAIN_A) + _zone_text(DOMAIN_A)
    assert "limit_req_status" in text, f"the rejection status is left at nginx's 503 default:\n{text}"
    assert "429" in text, f"the rejection status is not 429:\n{text}"


def test_gate_disabling_removes_every_directive(gate_home):
    """W8: an operator turning a feature off and finding it still active is the
    same class of failure as exposure that cannot be reversed.
    """
    import wpfy.site_security as site_security

    assert site_security.set_login_rate_limit(DOMAIN_A, True).exit_code == 0
    assert "limit_req" in _snippet_text(DOMAIN_A)

    assert site_security.set_login_rate_limit(DOMAIN_A, False).exit_code == 0
    snippet = _snippet_text(DOMAIN_A)
    assert "limit_req " not in snippet and "limit_req\t" not in snippet, (
        f"disabling left a rate-limit directive behind:\n{snippet}"
    )
    assert "wp-login" not in snippet, f"disabling left the wp-login block behind:\n{snippet}"
    assert site_security.load_security(DOMAIN_A).get("login_rate_limit") is False


def test_gate_enabling_twice_is_enabling_once(gate_home):
    """W9: the standing idempotency rule. A repeat after a partial failure is
    the normal recovery path.
    """
    import wpfy.site_security as site_security

    assert site_security.set_login_rate_limit(DOMAIN_A, True).exit_code == 0
    first_snippet, first_zone = _snippet_text(DOMAIN_A), _zone_text(DOMAIN_A)

    assert site_security.set_login_rate_limit(DOMAIN_A, True).exit_code == 0
    assert _snippet_text(DOMAIN_A) == first_snippet, "a repeat enable changed the snippet"
    assert _zone_text(DOMAIN_A) == first_zone, "a repeat enable changed the zone file"


def test_gate_stored_config_cannot_inject_nginx_directives(gate_home):
    """W10: `security.json` is a file on disk. A restore, a hand edit, or any
    future writer can put anything in it, and it is rendered straight into a
    config nginx executes. Every other value in this file is validated on read
    for exactly that reason.

    The precondition is load-bearing. Without it this gate passes against a
    codebase that has no such feature at all — an unknown key is dropped by
    `_validated_config`, nothing renders, and "correctly validated" is
    indistinguishable from "not implemented". This is the same vacuity that let
    23 of Phase 4b's 32 gates pass against a panel with none of its routes.
    """
    import wpfy.site_security as site_security

    assert site_security.set_login_rate_limit(DOMAIN_A, True).exit_code == 0
    assert "limit_req" in _snippet_text(DOMAIN_A), (
        "the rate limit does not render even when legitimately enabled, so the "
        "injection assertions below would pass against an absent feature"
    )

    for value in HOSTILE_RATE_VALUES:
        config = dict(site_security._DEFAULT_SECURITY)
        config["login_rate_limit"] = value
        site_security.save_security(DOMAIN_A, config)
        result = site_security.render_security(DOMAIN_A)
        snippet = _snippet_text(DOMAIN_A)
        assert "limit_req_zone" not in snippet, (
            f"{value!r} injected an http-context directive into the server snippet:\n{snippet}"
        )
        for marker in ("deny all", "server {", "evil"):
            assert marker not in snippet, (
                f"{value!r} injected {marker!r} into the generated config:\n{snippet}"
            )
        assert result.exit_code in (0, 3), f"{value!r} produced an unexpected result"


def test_gate_the_rest_of_the_hardening_survives(gate_home):
    """W11: anti-vacuity for W8 — "disabling removes the directives" is trivially
    satisfied by a renderer that emits nothing at all, for anything.
    """
    import wpfy.site_security as site_security

    assert site_security.add_deny_ip(DOMAIN_A, "203.0.113.0/24").exit_code == 0
    assert site_security.add_ua_block(DOMAIN_A, "BadBot").exit_code == 0
    assert site_security.set_login_rate_limit(DOMAIN_A, True).exit_code == 0

    snippet = _snippet_text(DOMAIN_A)
    assert "deny 203.0.113.0/24;" in snippet, f"enabling the limit dropped the IP deny list:\n{snippet}"
    assert "BadBot" in snippet, f"enabling the limit dropped the user-agent blocks:\n{snippet}"
    assert "limit_req" in snippet

    assert site_security.set_login_rate_limit(DOMAIN_A, False).exit_code == 0
    snippet = _snippet_text(DOMAIN_A)
    assert "deny 203.0.113.0/24;" in snippet, f"disabling the limit dropped the IP deny list:\n{snippet}"
    assert "BadBot" in snippet, f"disabling the limit dropped the user-agent blocks:\n{snippet}"


def test_gate_the_limit_keys_on_the_real_client_not_the_edge(gate_home):
    """W13: the gate that decides whether this feature protects a site or takes
    it offline.

    Every site's nginx sits behind Traefik, so `$binary_remote_addr` is
    *Traefik's* address unless the real-ip module is configured. Today
    `set_real_ip_from` is emitted only when `deny_ips` is non-empty — so a site
    that enables rate limiting and nothing else keys every request in the world
    to one address.

    That is not a weak limit, it is an outage: one shared bucket for the entire
    site, the first few visitors per second consume the burst, and everyone else
    gets 429 including the operator. The feature added to stop a brute force
    would do the brute forcer's job for them.
    """
    import wpfy.site_security as site_security
    import wpfy.traefik as traefik

    assert site_security.set_login_rate_limit(DOMAIN_A, True).exit_code == 0
    snippet = _snippet_text(DOMAIN_A)

    assert "set_real_ip_from" in snippet, (
        "rate limiting is enabled but real-ip trust is not configured, so every "
        f"request keys to Traefik's address and the whole site shares one bucket:\n{snippet}"
    )
    assert "real_ip_header" in snippet, f"no real_ip_header directive:\n{snippet}"
    for cidr in traefik.traefik_network_cidrs():
        assert cidr in snippet, (
            f"the edge network {cidr} is not a trusted real-ip source, so "
            f"X-Forwarded-For is ignored and the key stays wrong:\n{snippet}"
        )


def test_gate_the_zone_key_is_the_binary_client_address(gate_home):
    """W14: `$binary_remote_addr` over `$remote_addr` — 4 or 16 bytes instead of
    a text string, which is what makes a bounded zone hold a useful number of
    IPv6 clients. Keying on anything request-controlled is the header defect
    from P4 in nginx form.
    """
    import wpfy.site_security as site_security

    assert site_security.set_login_rate_limit(DOMAIN_A, True).exit_code == 0
    zones = _zone_text(DOMAIN_A)

    assert "$binary_remote_addr" in zones, (
        f"the zone is not keyed on the binary client address:\n{zones}"
    )
    for forbidden in ("$http_x_forwarded_for", "$http_x_real_ip", "$http_user_agent",
                      "$http_referer", "$http_cookie"):
        assert forbidden not in zones, (
            f"the zone is keyed on {forbidden}, which the client controls, so "
            f"every request can claim a fresh bucket:\n{zones}"
        )


def test_gate_concurrent_connections_are_capped(gate_home):
    """W15: `limit_req` counts requests and says nothing about sockets held open.
    A slow-drip client that opens many keep-alive connections and dribbles bytes
    never trips a request-rate limit while consuming worker slots.
    """
    import wpfy.site_security as site_security

    assert site_security.set_login_rate_limit(DOMAIN_A, True).exit_code == 0
    zones = _zone_text(DOMAIN_A)
    snippet = _snippet_text(DOMAIN_A)

    assert "limit_conn_zone" in zones, f"no connection-limit zone defined:\n{zones}"
    assert "limit_conn" in snippet, f"no connection limit applied:\n{snippet}"
    assert "limit_conn_status" in snippet or "limit_conn_status" in zones, (
        "the connection-limit rejection status is left at nginx's 503 default"
    )

    referenced = set(re.findall(r"limit_conn\s+([A-Za-z0-9_-]+)\s", snippet))
    defined = set(re.findall(r"limit_conn_zone[^;]*zone=([A-Za-z0-9_-]+):", zones))
    missing = referenced - defined
    assert not missing, (
        f"connection zones {sorted(missing)} are used but never defined; nginx "
        f"refuses to start:\n--- server ---\n{snippet}\n--- http ---\n{zones}"
    )


def test_gate_xmlrpc_stays_blocked(gate_home):
    """W12: `xmlrpc.php` is the other brute-force endpoint and it is already
    404'd in the generated server block. Adding a login rate limit is not a
    reason to start serving it instead.
    """
    import wpfy.site_layout as site_layout

    source = Path(site_layout.__file__).read_text(encoding="utf-8")
    assert "xmlrpc" in source, "the xmlrpc block disappeared from the generated nginx config"
    xmlrpc_lines = [line for line in source.splitlines() if "xmlrpc" in line]
    assert any("404" in line or "return 404" in line for line in xmlrpc_lines) or any(
        "404" in source.splitlines()[source.splitlines().index(line) + 1]
        for line in xmlrpc_lines
    ), f"xmlrpc.php is no longer returned as 404: {xmlrpc_lines}"
