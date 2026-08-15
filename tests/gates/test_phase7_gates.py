"""GATE TESTS — Phase 7a (panel auth, roles, 2FA).

These tests are the security and correctness contract for Phase 7a. They were
written before the implementation and encode decisions, not implementation
details, so a gate failing usually means the product regressed rather than that
the gate is out of date.

They are editable, and were immutable until 2026-08-15. Change one only when
the decision it pins has genuinely changed, never to make a red test green:
say in the commit which decision moved and why, and keep the gate asserting the
new one. A gate deleted or weakened to pass takes its invariant with it.

This file is deliberately self-contained: it depends only on the stdlib and the
`wpfy` package, never on other test modules or shared fixtures.

Scope note: panel exposure (`wpfy panel expose`, the Traefik file provider, the
systemd unit) and the panel login UI are Phase 7b and 7c and are NOT gated here.
The one exposure-adjacent gate present is G4, which only asserts that the
existing loopback bind refusal has not been loosened while wiring auth in.

What this phase can get wrong that nothing else catches:

    Every gate written so far asks the same question in a different costume:
    "is this *input* allowed?". The set of legal inputs was always finite — a
    flavor, a service name, a cache mode, an octal mode, a path inside a jail —
    so the answer could be checked against the input alone.

    Phase 7 changes the variable. The input is now fine; the *caller* is the
    question. And the callers being restricted are calling sixty routes that
    were written across six phases by an actor who was told, correctly at the
    time, that exactly one omnipotent operator existed. Not one of those routes
    was written with a second principal in mind.

    That inverts the failure mode. A Phase 6 bug was a bug in Phase 6's code. A
    Phase 7 bug is usually *absence* — a route nobody remembered to think about,
    which keeps behaving exactly as it did in Phase 2 and hands a site-manager
    another tenant's database password. Nothing in the diff shows it, because
    the defect is a line that was never written.

    So the central gates in this file refuse to name routes. They walk
    `panel._ROUTES` and require every entry to be denied unless it is on a short
    written allowlist. A route added in Phase 8 is therefore denied to a
    site-manager by default, and the person adding it has to make a deliberate
    decision to open it. Default-deny derived from the panel's own table is the
    only construction that survives its own author forgetting something.

    Four more things go wrong here and nowhere else:

    1. The panel gains a *new class of secret*. Until now every secret belonged
       to a site and lived in its `.env`. Password hashes, TOTP seeds, and live
       session tokens belong to the panel itself, and the panel is the thing
       that serializes state to JSON for a browser. A hash in an API response is
       an offline cracking target; a session token in the event log is a
       readable credential in a file wpfy writes on every mutation.
    2. `wpfy panel` today prints a URL with `#token=` in it, and that token is
       full admin. If that stays live after users exist, the entire role system
       is decorative: anyone who can read one line of terminal scrollback, shell
       history, or a systemd log is admin. The transition off the run token is
       the single highest-consequence line in the phase.
    3. TOTP is easy to implement so that it *demonstrates* correctly and is
       still bypassable. A code accepted twice is not second-factor
       authentication — it is a password with an expiry date, and shoulder-surf
       and phishing both replay inside the window. A skew window nobody bounded
       turns a 30-second code into an all-day one.
    4. Login is the only route that must work without credentials, which makes
       it the only place a blanket exemption can be written. An exemption
       matched by prefix (`/api/auth/`) rather than by declaration also exempts
       whatever `/api/auth/...` route gets added next.

Invariants locked here:
  A1   The user store is 0600 and stays 0600 after every mutation.
  A2   No plaintext password is stored, and two users sharing a password do not
       share a hash — i.e. the salt is per-user, not global.
  A3   Verification rejects a wrong password and fails closed on a corrupt
       record instead of raising or accepting.
  A4   No `wpfy panel` command accepts a panel password as an argv value.
  A5   Authenticating an unknown user still runs the KDF, so response time is
       not a user-existence oracle.
  B1   A successful login returns a token that authenticates a later request.
  B2   Session tokens are unguessable and never repeat.
  B3   Logout invalidates the token it was called with.
  B4   An idle session expires.
  B5   An absolute session lifetime is enforced regardless of activity.
  B6   Absent, malformed, and unknown bearer tokens are 401.
  B7   Session tokens are never written to disk.
  C1   Below the lockout threshold, an unknown user and a wrong password are
       byte-identical responses.
  C2   After the threshold, even the correct password is refused.
  C3   The lockout is recorded as an event.
  C4   Lockout is per-user: failures against one account do not lock another,
       and an untouched account still logs in.
  C5   Exactly the routes declaring `scope="public"` are reachable without a
       session, that set is exactly `{auth.login}`, and public routes do not
       consult `authorize()` at all.
  D1   TOTP matches the RFC 6238 test vectors.
  D2   Enrollment discloses the secret exactly once.
  D3   With TOTP enabled, a password alone does not log in.
  D4   The accepted skew window is bounded and enforced at its edges.
  D5   A TOTP code cannot be replayed.
  E1   A site-manager is refused every route outside a short written allowlist.
       Derived from the route table, so future routes are denied by default.
  E2   A site-manager is refused every site route for an unassigned domain.
  E3   Anti-vacuity for E1/E2: an admin is refused nothing, and a site-manager
       reaches its own assigned domain.
  E4   A site-manager cannot manage users, including itself, and cannot widen
       its own role or site assignment.
  E5   Every non-public route consults `authorize()`.
  E6   The list routes a site-manager may reach are filtered to its own sites,
       not merely permitted.
  E7   A site-scope route with no domain in its path is admin-only, so
       `POST /api/sites` cannot be reached by a site-manager.
  F1   No API response carries a password hash, salt, or TOTP secret.
  F2   The event log carries no password, hash, or session token.
  F3   `GET /api/auth/me` reports identity and scope without credentials.
  G1   With no users configured, the run token still works.
  G2   Once any user exists, the run token no longer authenticates.
  G3   `panel_url()` stops emitting `#token=` once users exist.
  G4   A non-loopback bind is still refused.

Contract pinned by these gates (the actor must match these names exactly):

  Module `wpfy.panel_auth`:
    users_path() -> Path                 <config>/panel-users.json, mode 0600
    add_user(username, password, *, role, sites=()) -> None
    remove_user(username) -> None
    list_users() -> list[dict]           never includes hash, salt, or secret
    set_password(username, password) -> None
    set_role(username, role) -> None
    assign_site(username, domain) -> None
    revoke_site(username, domain) -> None
    verify_password(username, password) -> bool
    enable_totp(username) -> tuple[str, str]     (base32 secret, otpauth:// URI)
    disable_totp(username) -> None
    login_required() -> bool             True once at least one user exists
    totp_code(secret: bytes, timestamp: float, *, digits: int = 6) -> str
    reset_state() -> None                clears in-memory sessions and lockouts
    ROLE_ADMIN = "admin"
    ROLE_SITE_MANAGER = "site-manager"
    SESSION_IDLE_SECONDS, SESSION_ABSOLUTE_SECONDS,
    MAX_LOGIN_FAILURES, LOCKOUT_SECONDS,
    TOTP_STEP_SECONDS, TOTP_SKEW_STEPS       module-level, read at use time

  On-disk record schema, one dict per user, so these gates can be precise about
  what must and must not appear in the file:
    {"username", "role", "sites", "password_hash", "password_salt",
     "totp_secret"}   — `totp_secret` is null while 2FA is disabled.

  Routes:
    POST   /api/auth/login    {username, password, totp?}
           200 {"token", "username", "role", "sites"} | 401 generic failure
    POST   /api/auth/logout   200
    GET    /api/auth/me       200 {"username", "role", "sites"}
    POST   /api/auth/totp     200 {"secret", "uri"}   self-enrollment, once
    DELETE /api/auth/totp     200                     self-disable
    GET    /api/users                                 admin only
    POST   /api/users         {username, password, role, sites?}   admin only
    PUT    /api/users/<username>   {role?, password?, sites?}      admin only
    DELETE /api/users/<username>                                   admin only
    DELETE /api/users/<username>/totp                              admin only

  `RouteMeta.scope` gains two values beyond the existing "site" and "system":
    "public"   reachable with no credentials at all. Only `auth.login`.
    "session"  reachable by any authenticated principal, whatever its role.

  Status codes are load-bearing and distinct:
    401  no principal — absent, malformed, unknown, or expired session.
    403  a real principal that is not allowed to do this.
  A UI that logs the operator out on 401 must not log them out for clicking a
  link they lack the role for, which is why these are not interchangeable.

  User management is admin-only *including self*: a site-manager cannot change
  its own password, role, or site list through the panel. TOTP enrollment is the
  deliberate exception and is why it lives under `/api/auth/totp` with no
  username in the path — a 2FA seed that travels via an administrator is worse
  than one that never leaves its owner.
"""

from __future__ import annotations

import base64
import http.client
import json
import os
import re
import stat as stat_module
import threading
import time
from pathlib import Path

import pytest

RUN_TOKEN = "phase7-run-token"
ASSIGNED_DOMAIN = "assigned.example"
OTHER_DOMAIN = "unassigned.example"

ADMIN_USER = "gate-admin"
ADMIN_PASSWORD = "PH7-admin-pw-3f81ca"
MANAGER_USER = "gate-manager"
MANAGER_PASSWORD = "PH7-manager-pw-9de204"
SHARED_PASSWORD = "PH7-shared-pw-identical"
# A username that belongs to nobody, for loops that walk `/api/users/<username>`
# routes with a live session and must not delete the account doing the walking.
THROWAWAY_USER = "gate-nobody"

SITE_SECRET_MARKER = "PH7-DB-SECRET-6c1ea7"
SITE_UID = 1807

# RFC 6238 Appendix B, SHA-1 rows. The seed is the ASCII string "12345678901234567890".
RFC6238_SEED = b"12345678901234567890"
RFC6238_VECTORS = (
    (59, "94287082"),
    (1111111109, "07081804"),
    (1111111111, "14050471"),
    (1234567890, "89005924"),
    (2000000000, "69279037"),
    (20000000000, "65353130"),
)

# Every action a site-manager may reach without a domain in the path. Anything
# not listed here, and not a site-scope route naming an assigned domain, must be
# refused. New routes land outside this set and are therefore denied by default,
# which is the entire reason E1 is derived rather than enumerated.
SITE_MANAGER_ALLOWED_ACTIONS = frozenset({
    "auth.me",
    "auth.logout",
    "auth.totp.enable",
    "auth.totp.disable",
    "site.list",
    "job.list",
    "job.read",
    "event.list",
    # The live feed behind the same permission as `event.list`. Safe for the
    # same reason and only that reason: `_stream_visible` drops any event whose
    # domain is not in the principal's assigned set, host-level events included.
    # `test_the_event_stream_filters_by_tenancy_not_just_permission` covers that
    # filter -- do not add a route here without one.
    "event.stream",
})

# The subset of the above that returns other tenants' rows unless it is filtered
# rather than merely permitted.
FILTERED_LIST_PATHS = ("/api/sites", "/api/jobs", "/api/events")

_GATE_ENV = (
    "WPFY_INSTALL_ROOT",
    "WPFY_CONFIG_DIR",
    "WPFY_STATE_DIR",
    "WPFY_LOG_DIR",
    "WPFY_SKIP_RUNTIME",
    "WPFY_SKIP_WORDPRESS_DOWNLOAD",
    "WPFY_SKIP_CHOWN",
)

_PATH_FIELDS = ("install_root", "config_dir", "state_dir", "log_dir")

_GROUP_PATTERN = re.compile(r"\(\?P<(\w+)>[^)]*\)")


class Response:
    def __init__(self, status: int, body: bytes, headers: list[tuple[str, str]]):
        self.status = status
        self.body = body
        self.headers = headers

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", "replace")

    def json(self) -> dict:
        return json.loads(self.text)

    def header(self, name: str) -> str | None:
        for key, value in self.headers:
            if key.lower() == name.lower():
                return value
        return None


class GateHome:
    def __init__(self, host: str, port: int, paths, root: Path):
        self.host = host
        self.port = port
        self.paths = paths
        self.root = root
        self.admin_token = ""
        self.manager_token = ""


def _seed_site(paths, domain: str, *, uid: int) -> Path:
    site = Path(paths.sites_dir) / domain
    (site / "nginx" / "extra").mkdir(parents=True, exist_ok=True)
    (site / "php").mkdir(parents=True, exist_ok=True)
    (site / "app").mkdir(parents=True, exist_ok=True)
    (site / "db-data").mkdir(parents=True, exist_ok=True)
    (site / ".env").write_text(
        f"DOMAIN={domain}\n"
        "SITE_FLAVOR=wp\n"
        f"COMPOSE_PROJECT_NAME={domain.replace('.', '-')}\n"
        "APP_ROOT=/var/www/html\n"
        "PHP_VERSION=8.4\n"
        f"SITE_UID={uid}\n"
        "LETSENCRYPT_MODE=disabled\n"
        "PAGE_CACHE=none\n"
        "REDIS_ENABLED=0\n"
        "DB_NAME=gatedb\n"
        "DB_USER=gatedb\n"
        f"DB_PASSWORD={SITE_SECRET_MARKER}\n"
        f"MARIADB_PASSWORD={SITE_SECRET_MARKER}\n"
        f"DB_ROOT_PASSWORD={SITE_SECRET_MARKER}\n"
        f"MARIADB_ROOT_PASSWORD={SITE_SECRET_MARKER}\n",
        encoding="utf-8",
    )
    (site / "compose.yaml").write_text("services: {}\n", encoding="utf-8")
    (site / "nginx" / "default.conf").write_text("server {\n    listen 8080;\n}\n", encoding="utf-8")
    (site / "nginx" / "extra" / "custom.conf").write_text("", encoding="utf-8")
    (site / "app" / "index.php").write_text("<?php echo 'gate';\n", encoding="utf-8")
    return site


@pytest.fixture
def gate_home(tmp_path):
    """A real loopback panel over an isolated home, with no users configured.

    Paths are redirected by mutating the frozen `settings.PATHS` singleton in
    place. `importlib.reload` is deliberately avoided: it reuses a module's
    __dict__, so symbols captured at import time by other test modules keep
    pointing at the old class while the module starts producing the new one,
    silently breaking unrelated tests with no possible teardown.

    The panel is started *before* any user is created, on purpose. The run-token
    transition (G1/G2) is only a real gate if the server cannot have decided at
    startup whether login is required.
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
    })
    for field in _PATH_FIELDS:
        object.__setattr__(paths, field, os.environ[f"WPFY_{field.upper()}"])
    Path(paths.state_dir).mkdir(parents=True, exist_ok=True)
    Path(paths.log_dir).mkdir(parents=True, exist_ok=True)
    Path(paths.config_dir).mkdir(parents=True, exist_ok=True)

    wpfy.registry._REGISTRY = None

    _seed_site(paths, ASSIGNED_DOMAIN, uid=SITE_UID)
    _seed_site(paths, OTHER_DOMAIN, uid=SITE_UID + 1)

    import wpfy.panel as panel
    import wpfy.panel_auth as panel_auth

    panel_auth.reset_state()

    config = panel.PanelConfig(host="127.0.0.1", port=0, token=RUN_TOKEN)
    server = panel.make_panel_server(config)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    home = GateHome("127.0.0.1", server.server_address[1], paths, tmp_path)
    try:
        yield home
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


@pytest.fixture
def gate_panel(gate_home):
    """`gate_home` plus one admin and one site-manager, both logged in.

    The site-manager is assigned exactly one of the two seeded sites. Two sites
    exist so that "refused" and "allowed" can be told apart by domain rather
    than by whether the panel happens to answer at all.
    """
    import wpfy.panel_auth as panel_auth

    panel_auth.add_user(ADMIN_USER, ADMIN_PASSWORD, role=panel_auth.ROLE_ADMIN)
    panel_auth.add_user(
        MANAGER_USER, MANAGER_PASSWORD,
        role=panel_auth.ROLE_SITE_MANAGER, sites=(ASSIGNED_DOMAIN,),
    )
    gate_home.admin_token = _login_token(gate_home, ADMIN_USER, ADMIN_PASSWORD)
    gate_home.manager_token = _login_token(gate_home, MANAGER_USER, MANAGER_PASSWORD)
    return gate_home


def _request(home, path, *, method="GET", token=None, body=None, headers=None, timeout=30,
             read_body=True) -> Response:
    """One request against the gate panel.

    `read_body=False` returns the status and headers without draining the body.
    The route table contains `GET /api/stream`, which is Server-Sent Events: it
    answers 200 and then never ends, and its keepalives keep resetting the
    socket timeout, so a sweep that reads every route's body blocks there for
    good. The sweeps assert on status codes, so they do not need the body.
    """
    connection = http.client.HTTPConnection(home.host, home.port, timeout=timeout)
    try:
        sent = dict(headers or {})
        if token is not None:
            sent["Authorization"] = f"Bearer {token}"
        payload = None
        if body is not None:
            payload = json.dumps(body).encode("utf-8")
            sent["Content-Type"] = "application/json"
        connection.request(method, path, body=payload, headers=sent)
        response = connection.getresponse()
        return Response(response.status, response.read() if read_body else b"", response.getheaders())
    finally:
        connection.close()


def _login(home, username, password, totp=None) -> Response:
    body = {"username": username, "password": password}
    if totp is not None:
        body["totp"] = totp
    return _request(home, "/api/auth/login", method="POST", body=body)


def _login_token(home, username, password, totp=None) -> str:
    response = _login(home, username, password, totp)
    assert response.status == 200, f"login for {username} failed: {response.status} {response.text}"
    token = response.json().get("token")
    assert isinstance(token, str) and token, f"login returned no token: {response.text}"
    return token


def _concrete_path(pattern, *, domain: str, username: str) -> str | None:
    """Turn a route regex into a requestable path, or None if not expressible."""
    fillers = {
        "domain": domain,
        "username": username,
        "name": "gatedb",
        "user": "gatedbuser",
        "job_id": "gatejob",
        "service": "web",
    }
    source = pattern.pattern.lstrip("^").rstrip("$")

    def replace(match):
        return fillers.get(match.group(1), "gatevalue")

    source = _GROUP_PATTERN.sub(replace, source)
    if re.search(r"[()\[\]?*+\\|]", source):
        return None
    return source


def _routes():
    import wpfy.panel as panel

    routes = getattr(panel, "ROUTES", None) or getattr(panel, "_ROUTES", None)
    assert routes, "the panel route table is not introspectable as ROUTES or _ROUTES"
    return routes


def _has_domain_group(route) -> bool:
    return "domain" in route.pattern.groupindex


def _users_file(home) -> Path:
    import wpfy.panel_auth as panel_auth

    return panel_auth.users_path()


def _records(home) -> list[dict]:
    raw = json.loads(_users_file(home).read_text(encoding="utf-8"))
    users = raw["users"] if isinstance(raw, dict) and "users" in raw else raw
    assert isinstance(users, list), f"user store is not a list of records: {type(users)}"
    return users


def _record(home, username: str) -> dict:
    for entry in _records(home):
        if entry.get("username") == username:
            return entry
    raise AssertionError(f"no stored record for {username}")


def _files_under(root: Path) -> list[Path]:
    return [path for path in root.rglob("*") if path.is_file()]


def _text_of(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


# ---------------------------------------------------------------------------
# A — the user store
# ---------------------------------------------------------------------------

def test_gate_user_store_is_owner_only_after_every_mutation(gate_panel):
    """A1: 0600 at creation is not enough; a rewrite that drops the mode is the
    realistic failure, because the safe-write path is written once and the
    mutations are written six times.
    """
    import wpfy.panel_auth as panel_auth

    path = _users_file(gate_panel)
    assert path.exists(), f"user store not created at {path}"

    mutations = (
        ("add_user", lambda: panel_auth.add_user("extra-user", "PH7-extra-pw", role=panel_auth.ROLE_ADMIN)),
        ("set_password", lambda: panel_auth.set_password("extra-user", "PH7-extra-pw-2")),
        ("set_role", lambda: panel_auth.set_role("extra-user", panel_auth.ROLE_SITE_MANAGER)),
        ("assign_site", lambda: panel_auth.assign_site("extra-user", OTHER_DOMAIN)),
        ("revoke_site", lambda: panel_auth.revoke_site("extra-user", OTHER_DOMAIN)),
        ("remove_user", lambda: panel_auth.remove_user("extra-user")),
    )
    for label, call in mutations:
        call()
        mode = stat_module.S_IMODE(path.stat().st_mode)
        assert mode == 0o600, f"user store is {oct(mode)} after {label}, expected 0o600"


def test_gate_passwords_are_salted_per_user_and_never_stored_plainly(gate_panel):
    """A2: a shared salt is invisible in every functional test — logins work,
    role checks work — and turns one cracked hash into every account.
    """
    import wpfy.panel_auth as panel_auth

    panel_auth.add_user("twin-a", SHARED_PASSWORD, role=panel_auth.ROLE_ADMIN)
    panel_auth.add_user("twin-b", SHARED_PASSWORD, role=panel_auth.ROLE_ADMIN)

    raw = _users_file(gate_panel).read_text(encoding="utf-8")
    for secret in (ADMIN_PASSWORD, MANAGER_PASSWORD, SHARED_PASSWORD):
        assert secret not in raw, "a plaintext password is stored in the user store"

    first = _record(gate_panel, "twin-a")
    second = _record(gate_panel, "twin-b")
    assert first["password_salt"] != second["password_salt"], (
        "two users share a password salt, so the store is globally salted; "
        "one precomputation then covers every account"
    )
    assert first["password_hash"] != second["password_hash"], (
        "two users with the same password have the same hash, which discloses "
        "that they share a password and makes the hashes interchangeable"
    )
    assert panel_auth.verify_password("twin-a", SHARED_PASSWORD)
    assert panel_auth.verify_password("twin-b", SHARED_PASSWORD)


def test_gate_verification_rejects_wrong_passwords_and_corrupt_records(gate_panel):
    """A3: a verifier that raises on a damaged record is a denial of service; a
    verifier that returns True on one is an authentication bypass. Neither is
    acceptable, and a truncated write is how a record gets damaged.
    """
    import wpfy.panel_auth as panel_auth

    assert panel_auth.verify_password(ADMIN_USER, ADMIN_PASSWORD) is True
    assert panel_auth.verify_password(ADMIN_USER, ADMIN_PASSWORD + "x") is False
    assert panel_auth.verify_password(ADMIN_USER, "") is False
    assert panel_auth.verify_password("no-such-user", ADMIN_PASSWORD) is False

    path = _users_file(gate_panel)
    raw = json.loads(path.read_text(encoding="utf-8"))
    users = raw["users"] if isinstance(raw, dict) and "users" in raw else raw
    for entry in users:
        if entry.get("username") == ADMIN_USER:
            entry["password_hash"] = "!!!not-hex!!!"
            entry["password_salt"] = ""
    path.write_text(json.dumps(raw), encoding="utf-8")

    assert panel_auth.verify_password(ADMIN_USER, ADMIN_PASSWORD) is False, (
        "a corrupt stored hash authenticated a login"
    )


def test_gate_no_panel_command_takes_a_password_as_an_argv_value(gate_panel):
    """A4: argv is readable by every local user through `ps`, and lands in shell
    history and in systemd's journal. The rest of the CLI has pre-existing
    `--password` options for site-level credentials; this gate is deliberately
    scoped to the `panel` subtree, which is the surface this phase adds.
    """
    import argparse

    import wpfy.cli as cli

    parser = cli.build_parser()
    panel_parser = None
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            panel_parser = action.choices.get("panel")
    assert panel_parser is not None, "no `wpfy panel` parser found"

    offenders = []

    def walk(node, trail):
        for action in node._actions:
            if isinstance(action, argparse._SubParsersAction):
                for name, sub in action.choices.items():
                    walk(sub, trail + [name])
                continue
            if action.nargs == 0:
                continue
            for option in action.option_strings:
                lowered = option.lower()
                if lowered.endswith("-stdin"):
                    continue
                if any(word in lowered for word in ("password", "secret", "totp")):
                    offenders.append(" ".join(trail) + " " + option)

    walk(panel_parser, ["panel"])
    assert not offenders, (
        "panel commands accept credentials as argv values: " + ", ".join(offenders)
    )


def test_gate_unknown_user_login_still_runs_the_kdf(gate_panel, monkeypatch):
    """A5: returning early for an unknown user makes login time a user
    directory. The fix is to hash against a dummy salt anyway; this asserts the
    work happened rather than measuring a clock, so it does not flake.

    This observes the call through the `hashlib` module object, so `panel_auth`
    has to reach the KDF as `hashlib.scrypt(...)`. A `from hashlib import scrypt`
    binds the function into the module at import and makes the call
    unobservable — the gate then reports zero calls, which reads as a
    short-circuit and is indistinguishable from one.
    """
    import hashlib

    import wpfy.panel_auth as panel_auth

    calls = []
    real = hashlib.scrypt

    def counting(*args, **kwargs):
        calls.append(1)
        return real(*args, **kwargs)

    monkeypatch.setattr(panel_auth.hashlib, "scrypt", counting)

    calls.clear()
    _login(gate_panel, "definitely-not-a-user", "whatever-password")
    unknown_calls = len(calls)

    calls.clear()
    _login(gate_panel, ADMIN_USER, "wrong-password")
    known_calls = len(calls)

    assert unknown_calls > 0, (
        "an unknown username short-circuits before the KDF runs, so login "
        "latency reveals which usernames exist"
    )
    assert unknown_calls == known_calls, (
        f"unknown user ran the KDF {unknown_calls} times, a known user "
        f"{known_calls} — the difference is still a timing oracle"
    )


# ---------------------------------------------------------------------------
# B — sessions
# ---------------------------------------------------------------------------

def test_gate_login_returns_a_usable_session_token(gate_panel):
    """B1: the anti-vacuity floor for this entire file. Every refusal gate below
    passes against a panel that refuses everyone, including the admin.
    """
    response = _request(gate_panel, "/api/sites", token=gate_panel.admin_token)
    assert response.status == 200, f"admin session rejected: {response.status} {response.text}"
    assert "sites" in response.json()


def test_gate_session_tokens_are_unguessable_and_never_repeat(gate_panel):
    """B2: a session token is a bearer credential with no second factor behind
    it. Anything short or derived from the username is a login bypass.
    """
    tokens = {_login_token(gate_panel, ADMIN_USER, ADMIN_PASSWORD) for _ in range(5)}
    assert len(tokens) == 5, "logging in repeatedly returned a repeated session token"
    for token in tokens:
        assert len(token) >= 32, f"session token is only {len(token)} characters: too little entropy"
        assert ADMIN_USER not in token, "the session token embeds the username"
        assert ADMIN_PASSWORD not in token, "the session token embeds the password"


def test_gate_logout_invalidates_the_session(gate_panel):
    """B3: a logout that only clears browser storage leaves a live credential in
    every log, proxy, and terminal that saw it.
    """
    token = _login_token(gate_panel, ADMIN_USER, ADMIN_PASSWORD)
    assert _request(gate_panel, "/api/auth/me", token=token).status == 200

    logout = _request(gate_panel, "/api/auth/logout", method="POST", token=token, body={})
    assert logout.status == 200, f"logout failed: {logout.status} {logout.text}"

    after = _request(gate_panel, "/api/auth/me", token=token)
    assert after.status == 401, f"a logged-out token still authenticates: {after.status} {after.text}"


def test_gate_idle_sessions_expire(gate_panel, monkeypatch):
    """B4: the constants are read at use time on purpose — a deadline captured
    into a default argument at import cannot be tested and cannot be tuned.
    """
    import wpfy.panel_auth as panel_auth

    monkeypatch.setattr(panel_auth, "SESSION_IDLE_SECONDS", 0.5)
    token = _login_token(gate_panel, ADMIN_USER, ADMIN_PASSWORD)
    assert _request(gate_panel, "/api/auth/me", token=token).status == 200

    time.sleep(0.8)
    after = _request(gate_panel, "/api/auth/me", token=token)
    assert after.status == 401, f"an idle session past its deadline still works: {after.status}"


def test_gate_absolute_session_lifetime_is_enforced(gate_panel, monkeypatch):
    """B5: idle expiry alone never ends a session that is being used, so a stolen
    token stays valid for as long as the thief keeps polling.
    """
    import wpfy.panel_auth as panel_auth

    monkeypatch.setattr(panel_auth, "SESSION_ABSOLUTE_SECONDS", 0.5)
    token = _login_token(gate_panel, ADMIN_USER, ADMIN_PASSWORD)

    deadline = time.time() + 0.8
    while time.time() < deadline:
        _request(gate_panel, "/api/auth/me", token=token)
        time.sleep(0.1)

    after = _request(gate_panel, "/api/auth/me", token=token)
    assert after.status == 401, (
        f"a continuously used session outlived its absolute lifetime: {after.status}"
    )


def test_gate_bad_bearer_tokens_are_unauthenticated(gate_panel):
    """B6: 401 and not 403 — there is no principal here to deny."""
    for label, headers in (
        ("no header", {}),
        ("empty bearer", {"Authorization": "Bearer "}),
        ("not bearer", {"Authorization": f"Basic {ADMIN_USER}"}),
        ("unknown token", {"Authorization": "Bearer aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}),
        ("run token", {"Authorization": f"Bearer {RUN_TOKEN}"}),
    ):
        response = _request(gate_panel, "/api/sites", headers=headers)
        assert response.status == 401, f"{label} was not rejected as unauthenticated: {response.status}"


def test_gate_session_tokens_are_never_written_to_disk(gate_panel):
    """B7: sessions are in-memory by design. A token that reaches the user store,
    the event log, or a state file is a credential at rest with no expiry that
    anyone reading the file has to honour.
    """
    token = gate_panel.admin_token
    _request(gate_panel, "/api/sites", token=token)
    _request(gate_panel, f"/api/sites/{ASSIGNED_DOMAIN}/cache", token=token)

    leaked = [
        str(path) for path in _files_under(gate_panel.root)
        if token in _text_of(path)
    ]
    assert not leaked, f"the session token was written to disk: {leaked}"


# ---------------------------------------------------------------------------
# C — login hardening
# ---------------------------------------------------------------------------

def test_gate_unknown_user_and_wrong_password_are_indistinguishable(gate_panel):
    """C1: "no such user" versus "wrong password" turns the login form into a
    directory of every account on the box, which is step one of any credential
    stuffing run.
    """
    unknown = _login(gate_panel, "definitely-not-a-user", "some-password")
    wrong = _login(gate_panel, ADMIN_USER, "definitely-the-wrong-password")

    assert unknown.status == 401, f"unknown user did not return 401: {unknown.status}"
    assert wrong.status == 401, f"wrong password did not return 401: {wrong.status}"
    assert unknown.body == wrong.body, (
        "unknown user and wrong password return different bodies, which "
        f"enumerates accounts:\n  unknown: {unknown.text}\n  wrong:   {wrong.text}"
    )
    assert ADMIN_USER not in wrong.text, "the failure body echoes the username back"


def test_gate_lockout_refuses_even_the_correct_password(gate_panel):
    """C2: throttling that still accepts the right password on attempt 10000 is
    a rate limit, not a lockout, and offline-speed guessing beats it.
    """
    import wpfy.panel_auth as panel_auth

    assert panel_auth.MAX_LOGIN_FAILURES <= 10, (
        f"MAX_LOGIN_FAILURES is {panel_auth.MAX_LOGIN_FAILURES}; a threshold this "
        "high is not a lockout"
    )
    assert panel_auth.LOCKOUT_SECONDS >= 30, (
        f"LOCKOUT_SECONDS is {panel_auth.LOCKOUT_SECONDS}; a window this short "
        "does not slow an automated guesser down"
    )

    for _ in range(panel_auth.MAX_LOGIN_FAILURES):
        _login(gate_panel, ADMIN_USER, "wrong-password")

    response = _login(gate_panel, ADMIN_USER, ADMIN_PASSWORD)
    assert response.status != 200, (
        "the correct password was accepted after "
        f"{panel_auth.MAX_LOGIN_FAILURES} consecutive failures, so there is no lockout"
    )
    assert "token" not in response.text, "a locked-out login still handed out a token"


def test_gate_lockout_is_recorded_as_an_event(gate_panel):
    """C3: a lockout nobody can see is an outage report, not a security signal.
    The panel already has an event log; this belongs in it.
    """
    import wpfy.events as events
    import wpfy.panel_auth as panel_auth

    for _ in range(panel_auth.MAX_LOGIN_FAILURES + 1):
        _login(gate_panel, ADMIN_USER, "wrong-password")

    recorded = events.list_events(limit=200)
    blob = json.dumps(recorded)
    assert any("lock" in json.dumps(entry).lower() for entry in recorded), (
        f"no lockout event was recorded; events seen: {blob[:400]}"
    )


def test_gate_lockout_is_per_user(gate_panel):
    """C4: anti-vacuity for C2, and a denial-of-service gate in its own right.
    A global counter lets anyone lock every administrator out of the panel by
    guessing at a username they invented.
    """
    import wpfy.panel_auth as panel_auth

    for _ in range(panel_auth.MAX_LOGIN_FAILURES + 2):
        _login(gate_panel, ADMIN_USER, "wrong-password")

    response = _login(gate_panel, MANAGER_USER, MANAGER_PASSWORD)
    assert response.status == 200, (
        "locking one account out also locked out an untouched account: "
        f"{response.status} {response.text}"
    )


def test_gate_only_declared_public_routes_are_reachable_without_a_session(gate_panel, monkeypatch):
    """C5: login has to work without credentials, which makes it the one place a
    blanket exemption can be written. A prefix exemption on `/api/auth/` also
    exempts whatever `/api/auth/...` route is added next — so the exemption must
    be a per-route declaration, and this derives the set from that declaration.
    """
    import wpfy.panel as panel

    routes = _routes()
    public_actions = {route.meta.action for route in routes if route.meta.scope == "public"}
    assert public_actions == {"auth.login"}, (
        f"routes declared public are {sorted(public_actions)}; only auth.login may be"
    )

    reachable = []
    for route in routes:
        path = _concrete_path(route.pattern, domain=ASSIGNED_DOMAIN, username=ADMIN_USER)
        if path is None:
            continue
        body = {} if route.method != "GET" else None
        response = _request(gate_panel, path, method=route.method, body=body, read_body=False)
        if response.status != 401 and route.meta.scope != "public":
            reachable.append(f"{route.method} {path} [{route.meta.action}] -> {response.status}")
    assert not reachable, "routes reachable with no credentials:\n  " + "\n  ".join(reachable)

    def refuse(*args, **kwargs):
        raise panel.PanelError(403, "authorize was consulted")

    monkeypatch.setattr(panel, "authorize", refuse)
    response = _login(gate_panel, ADMIN_USER, ADMIN_PASSWORD)
    assert response.status == 200, (
        "the login route is dispatched through authorize(), so it can only ever "
        "succeed for someone who is already authorized"
    )


# ---------------------------------------------------------------------------
# D — TOTP
# ---------------------------------------------------------------------------

def test_gate_totp_matches_rfc6238_vectors(gate_panel):
    """D1: an implementation off by one time-step, or truncating the wrong four
    bytes, still produces six plausible digits that verify against itself. The
    published vectors are the only thing that catches it.
    """
    import wpfy.panel_auth as panel_auth

    for timestamp, expected in RFC6238_VECTORS:
        produced = panel_auth.totp_code(RFC6238_SEED, timestamp, digits=8)
        assert produced == expected, (
            f"RFC 6238 vector at T={timestamp}: expected {expected}, got {produced}"
        )
    assert panel_auth.totp_code(RFC6238_SEED, 59) == RFC6238_VECTORS[0][1][-6:], (
        "the 6-digit code is not the low 6 digits of the RFC's 8-digit vector"
    )


def test_gate_totp_enrollment_discloses_the_secret_once(gate_panel):
    """D2: a secret that can be re-read is not a second factor for anyone who
    already holds a session — which is exactly the attacker 2FA exists to stop.
    """
    first = _request(gate_panel, "/api/auth/totp", method="POST",
                     token=gate_panel.manager_token, body={})
    assert first.status == 200, f"TOTP enrollment failed: {first.status} {first.text}"
    payload = first.json()
    secret = payload.get("secret")
    uri = payload.get("uri", "")
    assert isinstance(secret, str) and secret, f"enrollment returned no secret: {payload}"
    assert uri.startswith("otpauth://totp/"), f"enrollment returned no otpauth URI: {uri!r}"
    assert secret in uri, "the otpauth URI does not carry the secret it enrolls"

    second = _request(gate_panel, "/api/auth/totp", method="POST",
                      token=gate_panel.manager_token, body={})
    assert secret not in second.text, (
        "re-requesting enrollment disclosed the existing secret again; it must "
        "either refuse or rotate, never re-read"
    )

    for path in ("/api/auth/me", "/api/users"):
        response = _request(gate_panel, path, token=gate_panel.admin_token)
        assert secret not in response.text, f"{path} discloses a TOTP secret"


def test_gate_totp_is_required_once_enabled(gate_panel):
    """D3: enrollment that does not change the login path is a settings toggle
    with no effect, and it passes every test that only checks enrollment.
    """
    import wpfy.panel_auth as panel_auth

    secret_b32, _ = panel_auth.enable_totp(MANAGER_USER)
    secret = base64.b32decode(secret_b32, casefold=True)

    without = _login(gate_panel, MANAGER_USER, MANAGER_PASSWORD)
    assert without.status == 401, (
        f"a password alone logged in a TOTP-enabled user: {without.status} {without.text}"
    )

    wrong = _login(gate_panel, MANAGER_USER, MANAGER_PASSWORD, totp="000000")
    assert wrong.status == 401, f"a wrong TOTP code was accepted: {wrong.status}"

    code = panel_auth.totp_code(secret, time.time())
    good = _login(gate_panel, MANAGER_USER, MANAGER_PASSWORD, totp=code)
    assert good.status == 200, f"the correct TOTP code was refused: {good.status} {good.text}"


def test_gate_totp_skew_window_is_bounded_and_enforced(gate_panel):
    """D4: clock drift needs a window; an unbounded one hands an attacker every
    code ever generated. The edges are tested against the shipped constants, so
    this stays honest whatever window is chosen.
    """
    import wpfy.panel_auth as panel_auth

    assert panel_auth.TOTP_SKEW_STEPS <= 2, (
        f"TOTP_SKEW_STEPS is {panel_auth.TOTP_SKEW_STEPS}; a window that wide "
        "keeps old codes alive for minutes"
    )
    assert panel_auth.TOTP_STEP_SECONDS == 30, (
        f"TOTP_STEP_SECONDS is {panel_auth.TOTP_STEP_SECONDS}; RFC 6238 clients "
        "including every authenticator app assume 30"
    )

    secret_b32, _ = panel_auth.enable_totp(MANAGER_USER)
    secret = base64.b32decode(secret_b32, casefold=True)
    step = panel_auth.TOTP_STEP_SECONDS
    # Anchored to the middle of the current step, not to `now`. A code generated
    # at 29.9s into a step lands one step earlier by the time the server
    # evaluates it, which would make the edge assertions below flake roughly
    # once per thirty runs for reasons that have nothing to do with the code.
    now = (time.time() // step) * step + step / 2

    edge = panel_auth.totp_code(secret, now - panel_auth.TOTP_SKEW_STEPS * step)
    accepted = _login(gate_panel, MANAGER_USER, MANAGER_PASSWORD, totp=edge)
    assert accepted.status == 200, (
        f"a code {panel_auth.TOTP_SKEW_STEPS} step(s) old was refused although "
        "TOTP_SKEW_STEPS says it is inside the window"
    )

    stale = panel_auth.totp_code(secret, now - (panel_auth.TOTP_SKEW_STEPS + 2) * step)
    refused = _login(gate_panel, MANAGER_USER, MANAGER_PASSWORD, totp=stale)
    assert refused.status == 401, (
        f"a code {panel_auth.TOTP_SKEW_STEPS + 2} steps old was accepted, so the "
        "skew window is wider than it declares"
    )


def test_gate_totp_codes_cannot_be_replayed(gate_panel):
    """D5: RFC 6238 section 5.2 — a code accepted twice is a password with a
    short life, not a second factor. Anyone who saw the screen, the phishing
    proxy, or the shoulder has the whole window to reuse it.
    """
    import wpfy.panel_auth as panel_auth

    secret_b32, _ = panel_auth.enable_totp(MANAGER_USER)
    secret = base64.b32decode(secret_b32, casefold=True)

    code = panel_auth.totp_code(secret, time.time())
    first = _login(gate_panel, MANAGER_USER, MANAGER_PASSWORD, totp=code)
    assert first.status == 200, f"the first use of a valid code failed: {first.text}"

    second = _login(gate_panel, MANAGER_USER, MANAGER_PASSWORD, totp=code)
    assert second.status == 401, (
        "the same TOTP code logged in twice; a replayed code must be refused "
        "for the remainder of its time step"
    )


# ---------------------------------------------------------------------------
# E — the role boundary
# ---------------------------------------------------------------------------

def test_gate_site_manager_is_refused_every_route_outside_its_allowlist(gate_panel):
    """E1: the load-bearing gate of this phase, and the reason it is derived.

    Sixty routes were written across six phases under the correct assumption
    that exactly one omnipotent operator existed. The realistic Phase 7 defect
    is not a wrong check; it is a route nobody remembered, still behaving as it
    did in Phase 2. Deriving the deny set from the panel's own table means a
    route added in Phase 8 is refused by default and has to be deliberately
    opened, rather than being open until somebody notices.
    """
    denied_shortfall = []
    for route in _routes():
        if route.meta.scope == "public":
            continue
        if route.meta.action in SITE_MANAGER_ALLOWED_ACTIONS:
            continue
        if route.meta.scope == "site" and _has_domain_group(route):
            continue  # covered by E2, which varies the domain instead
        path = _concrete_path(route.pattern, domain=ASSIGNED_DOMAIN, username=MANAGER_USER)
        if path is None:
            continue
        body = {} if route.method != "GET" else None
        response = _request(gate_panel, path, method=route.method,
                            token=gate_panel.manager_token, body=body, read_body=False)
        if response.status != 403:
            denied_shortfall.append(
                f"{route.method} {path} [{route.meta.action}] -> {response.status}"
            )
    assert not denied_shortfall, (
        "a site-manager reached routes outside its allowlist:\n  "
        + "\n  ".join(denied_shortfall)
    )


def test_gate_site_manager_is_refused_unassigned_domains(gate_panel):
    """E2: the tenancy boundary. Every site route names its domain in the path,
    so the check has exactly one place to live and exactly one way to be
    forgotten — on the route whose handler resolves the domain itself.
    """
    escaped = []
    for route in _routes():
        if route.meta.scope != "site" or not _has_domain_group(route):
            continue
        path = _concrete_path(route.pattern, domain=OTHER_DOMAIN, username=MANAGER_USER)
        if path is None:
            continue
        body = {} if route.method != "GET" else None
        response = _request(gate_panel, path, method=route.method,
                            token=gate_panel.manager_token, body=body, read_body=False)
        if response.status != 403:
            escaped.append(f"{route.method} {path} [{route.meta.action}] -> {response.status}")
        if SITE_SECRET_MARKER in response.text:
            escaped.append(f"{route.method} {path} LEAKED THE OTHER SITE'S DB PASSWORD")
    assert not escaped, (
        "a site-manager reached an unassigned site:\n  " + "\n  ".join(escaped)
    )


def test_gate_authorized_principals_are_refused_nothing(gate_panel):
    """E3: anti-vacuity for E1 and E2, in both directions at once.

    Every refusal gate in this file passes against a panel that answers 403 to
    everyone. This one is the reason they mean something.

    Three exclusions, all to stop the loop destroying the state it is walking:

    * Destructive routes are skipped, because deleting the site mid-loop makes
      every later route 404 — still "not 403", so the gate would keep passing
      while testing nothing. The refusal gates above do cover them.
    * The username filler is a name that belongs to nobody, because
      `DELETE /api/users/<username>` is not destructive in the route table's
      sense and would otherwise delete the admin doing the walking.
    * `auth.logout` is skipped because it revokes the very credential this loop
      authenticates with. Without this the gate passes only while logout happens
      to be declared last in the route table, and fails — loudly, and for a
      reason having nothing to do with authorization — the day somebody reorders
      it. A gate that depends on declaration order is not testing what it says.
    """
    admin_refused = []
    manager_refused = []
    for route in _routes():
        if route.meta.scope == "public" or route.meta.action == "auth.logout":
            continue
        path = _concrete_path(route.pattern, domain=ASSIGNED_DOMAIN, username=THROWAWAY_USER)
        if path is None:
            continue
        body = {} if route.method != "GET" else None
        if route.meta.destructive:
            continue
        response = _request(gate_panel, path, method=route.method,
                            token=gate_panel.admin_token, body=body, read_body=False)
        if response.status in (401, 403):
            admin_refused.append(f"{route.method} {path} [{route.meta.action}] -> {response.status}")

        if route.meta.scope != "site" or not _has_domain_group(route):
            continue
        manager_path = _concrete_path(route.pattern, domain=ASSIGNED_DOMAIN, username=THROWAWAY_USER)
        response = _request(gate_panel, manager_path, method=route.method,
                            token=gate_panel.manager_token, body=body, read_body=False)
        if response.status in (401, 403):
            manager_refused.append(
                f"{route.method} {manager_path} [{route.meta.action}] -> {response.status}"
            )

    assert not admin_refused, "an admin was refused:\n  " + "\n  ".join(admin_refused)
    assert not manager_refused, (
        "a site-manager was refused its own assigned site:\n  " + "\n  ".join(manager_refused)
    )


def test_gate_site_manager_cannot_manage_users(gate_panel):
    """E4: privilege escalation is the whole game. Self-service is deliberately
    included — user management is admin-only including one's own record, so
    there is no "but it's only my own account" path to widen a role through.
    """
    import wpfy.panel_auth as panel_auth

    attempts = (
        ("list users", "GET", "/api/users", None),
        ("create an admin", "POST", "/api/users",
         {"username": "smuggled", "password": "PH7-smuggled-pw", "role": panel_auth.ROLE_ADMIN}),
        ("promote self", "PUT", f"/api/users/{MANAGER_USER}", {"role": panel_auth.ROLE_ADMIN}),
        ("self-assign a site", "PUT", f"/api/users/{MANAGER_USER}",
         {"sites": [ASSIGNED_DOMAIN, OTHER_DOMAIN]}),
        ("change own password", "PUT", f"/api/users/{MANAGER_USER}", {"password": "PH7-new-pw"}),
        ("promote via admin record", "PUT", f"/api/users/{ADMIN_USER}",
         {"role": panel_auth.ROLE_SITE_MANAGER}),
        ("delete the admin", "DELETE", f"/api/users/{ADMIN_USER}", None),
        ("strip the admin's 2FA", "DELETE", f"/api/users/{ADMIN_USER}/totp", None),
    )
    for label, method, path, body in attempts:
        response = _request(gate_panel, path, method=method,
                            token=gate_panel.manager_token, body=body)
        assert response.status == 403, (
            f"a site-manager could {label}: {response.status} {response.text}"
        )

    assert _record(gate_panel, MANAGER_USER)["role"] == panel_auth.ROLE_SITE_MANAGER
    assert list(_record(gate_panel, MANAGER_USER)["sites"]) == [ASSIGNED_DOMAIN]
    assert _record(gate_panel, ADMIN_USER)["role"] == panel_auth.ROLE_ADMIN
    assert not any(entry.get("username") == "smuggled" for entry in _records(gate_panel))
    assert _request(gate_panel, "/api/auth/me", token=gate_panel.admin_token).status == 200, (
        "the admin session stopped working, so the assertions above prove nothing"
    )


def test_gate_every_non_public_route_consults_authorize(gate_panel, monkeypatch):
    """E5: the Phase 1 seam only holds if every route actually goes through it.
    A handler that resolves a domain itself, or a dispatcher shortcut added for
    one convenient route, bypasses every role check in one line.
    """
    import wpfy.panel as panel

    def refuse(principal, meta, domain):
        raise panel.PanelError(403, "gate: authorize was not consulted")

    monkeypatch.setattr(panel, "authorize", refuse)

    bypassed = []
    for route in _routes():
        if route.meta.scope == "public":
            continue
        path = _concrete_path(route.pattern, domain=ASSIGNED_DOMAIN, username=ADMIN_USER)
        if path is None:
            continue
        body = {} if route.method != "GET" else None
        response = _request(gate_panel, path, method=route.method,
                            token=gate_panel.admin_token, body=body, read_body=False)
        if response.status != 403:
            bypassed.append(f"{route.method} {path} [{route.meta.action}] -> {response.status}")
    assert not bypassed, (
        "routes answered without consulting authorize():\n  " + "\n  ".join(bypassed)
    )


def test_gate_list_routes_are_filtered_not_merely_permitted(gate_panel):
    """E6: refusing a route and filtering a route are different mechanisms, and
    only one of them was on anybody's checklist. `/api/sites` has to stay
    reachable or a site-manager has no navigation at all — so it is the one
    place where "allowed" has to mean "allowed, minus everyone else's rows".

    Jobs and events are here for a reason that is easy to miss: site operations
    answer 202 with a job id, so a site-manager who cannot poll `/api/jobs`
    cannot see the result of anything they are allowed to start.
    """
    import wpfy.panel_jobs as panel_jobs

    panel_jobs.create_job("site.backup", domain=ASSIGNED_DOMAIN)
    foreign = panel_jobs.create_job("site.backup", domain=OTHER_DOMAIN)

    import wpfy.events as events

    events.record_event("site.backup", domain=ASSIGNED_DOMAIN, actor=MANAGER_USER)
    events.record_event("site.backup", domain=OTHER_DOMAIN, actor=ADMIN_USER)

    for path in FILTERED_LIST_PATHS:
        response = _request(gate_panel, path, token=gate_panel.manager_token)
        assert response.status == 200, f"{path} refused a site-manager: {response.status}"
        assert OTHER_DOMAIN not in response.text, (
            f"{path} disclosed an unassigned site to a site-manager:\n{response.text[:400]}"
        )
        assert ASSIGNED_DOMAIN in response.text, (
            f"{path} returned nothing at all, so the filter cannot be distinguished "
            f"from an empty implementation:\n{response.text[:400]}"
        )

    response = _request(gate_panel, f"/api/jobs/{foreign.id}", token=gate_panel.manager_token)
    assert response.status == 403, (
        f"a site-manager read another site's job by id: {response.status} {response.text}"
    )

    admin_view = _request(gate_panel, "/api/sites", token=gate_panel.admin_token)
    assert OTHER_DOMAIN in admin_view.text, (
        "the admin cannot see all sites either, so the filter is not role-based"
    )


def test_gate_site_routes_without_a_domain_are_admin_only(gate_panel):
    """E7: `POST /api/sites` is declared site-scope but carries no domain, so a
    check written as "deny if the domain is not assigned" reads `domain=None`,
    finds nothing to compare, and lets a site-manager create sites — and the
    creator of a site is by construction assigned to it.
    """
    offenders = []
    for route in _routes():
        if route.meta.scope != "site" or _has_domain_group(route):
            continue
        path = _concrete_path(route.pattern, domain=ASSIGNED_DOMAIN, username=MANAGER_USER)
        if path is None:
            continue
        body = {} if route.method != "GET" else None
        response = _request(gate_panel, path, method=route.method,
                            token=gate_panel.manager_token, body=body, read_body=False)
        if response.status != 403:
            offenders.append(f"{route.method} {path} [{route.meta.action}] -> {response.status}")
    creation = _request(gate_panel, "/api/sites", method="POST", token=gate_panel.manager_token,
                        body={"domain": "smuggled.example", "flavor": "php"}, read_body=False)
    assert creation.status == 403, (
        f"a site-manager created a site: {creation.status} {creation.text}"
    )
    assert not (Path(gate_panel.paths.sites_dir) / "smuggled.example").exists()
    assert not offenders, (
        "site-scope routes with no domain in the path reached a site-manager:\n  "
        + "\n  ".join(offenders)
    )


# ---------------------------------------------------------------------------
# F — secret hygiene
# ---------------------------------------------------------------------------

def test_gate_no_api_response_carries_credential_material(gate_panel):
    """F1: the panel serializes its own state to JSON for a browser, and its own
    state now includes password hashes. A hash in a response is an offline
    cracking target handed to whoever holds the weakest session.
    """
    import wpfy.panel_auth as panel_auth

    secret_b32, _ = panel_auth.enable_totp(MANAGER_USER)
    record = _record(gate_panel, ADMIN_USER)
    markers = {
        "password hash": record["password_hash"],
        "password salt": record["password_salt"],
        "totp secret": secret_b32,
        "admin password": ADMIN_PASSWORD,
    }

    leaks = []
    for route in _routes():
        if route.method != "GET" or route.meta.scope == "public":
            continue
        path = _concrete_path(route.pattern, domain=ASSIGNED_DOMAIN, username=ADMIN_USER)
        if path is None:
            continue
        response = _request(gate_panel, path, token=gate_panel.admin_token, read_body=False)
        for label, marker in markers.items():
            if marker and marker in response.text:
                leaks.append(f"{path} disclosed the {label}")

    listed = panel_auth.list_users()
    for entry in listed:
        blob = json.dumps(entry)
        for label, marker in markers.items():
            if marker and marker in blob:
                leaks.append(f"panel_auth.list_users() disclosed the {label}")

    assert not leaks, "credential material reached a response:\n  " + "\n  ".join(leaks)


def test_gate_event_log_carries_no_credentials(gate_panel):
    """F2: the event log is the one file wpfy appends to on every mutation, it is
    the file an operator tails when something breaks, and it is the file that
    ends up in a bug report. A session token in it is a live credential in a
    paste.
    """
    import wpfy.events as events
    import wpfy.panel_auth as panel_auth

    token = _login_token(gate_panel, ADMIN_USER, ADMIN_PASSWORD)
    _request(gate_panel, f"/api/sites/{ASSIGNED_DOMAIN}/cache", method="PUT",
             token=token, body={"page_cache": "none"})
    _login(gate_panel, ADMIN_USER, "wrong-password")
    _request(gate_panel, "/api/users", method="POST", token=token,
             body={"username": "logged-user", "password": "PH7-logged-pw", "role": panel_auth.ROLE_ADMIN})
    _request(gate_panel, "/api/auth/logout", method="POST", token=token, body={})

    record = _record(gate_panel, ADMIN_USER)
    forbidden = {
        "session token": token,
        "admin password": ADMIN_PASSWORD,
        "new user password": "PH7-logged-pw",
        "password hash": record["password_hash"],
        "password salt": record["password_salt"],
    }
    blob = _text_of(events.event_log_path())
    found = [label for label, value in forbidden.items() if value and value in blob]
    assert not found, f"the event log contains: {', '.join(found)}"


def test_gate_auth_me_reports_scope_without_credentials(gate_panel):
    """F3: the UI decides what to render from this response, so it has to carry
    the role and the site list — and nothing a stolen response could be replayed
    with.
    """
    response = _request(gate_panel, "/api/auth/me", token=gate_panel.manager_token)
    assert response.status == 200, f"/api/auth/me failed: {response.status} {response.text}"
    payload = response.json()
    assert payload.get("username") == MANAGER_USER
    assert payload.get("role") == "site-manager"
    assert list(payload.get("sites") or []) == [ASSIGNED_DOMAIN]
    for banned in ("password", "hash", "salt", "secret", "token"):
        assert banned not in json.dumps(payload).lower(), (
            f"/api/auth/me mentions {banned!r}: {payload}"
        )


# ---------------------------------------------------------------------------
# G — the run-token transition
# ---------------------------------------------------------------------------

def test_gate_run_token_works_while_no_users_exist(gate_home):
    """G1: anti-vacuity for G2, and the compatibility promise. `wpfy panel` on a
    fresh box has no user store and must still open.
    """
    import wpfy.panel_auth as panel_auth

    assert panel_auth.login_required() is False, "login is required before any user exists"
    response = _request(gate_home, "/api/sites", token=RUN_TOKEN)
    assert response.status == 200, (
        f"the run token does not work on a panel with no users: {response.status} {response.text}"
    )


def test_gate_run_token_dies_once_a_user_exists(gate_home):
    """G2: the highest-consequence line in the phase.

    The run token is full admin, it is printed to a terminal, and it survives in
    scrollback, shell history, and the journal. If it keeps working after roles
    exist then the roles are decorative — every restriction in this file is
    bypassed by one line of `wpfy panel` output.
    """
    import wpfy.panel_auth as panel_auth

    assert _request(gate_home, "/api/sites", token=RUN_TOKEN).status == 200

    panel_auth.add_user(ADMIN_USER, ADMIN_PASSWORD, role=panel_auth.ROLE_ADMIN)
    assert panel_auth.login_required() is True, "login is not required although a user exists"

    for path in ("/api/sites", "/api/overview", f"/api/sites/{ASSIGNED_DOMAIN}"):
        response = _request(gate_home, path, token=RUN_TOKEN)
        assert response.status == 401, (
            f"the run token still authenticates {path} after a user was created: "
            f"{response.status} {response.text}"
        )

    token = _login_token(gate_home, ADMIN_USER, ADMIN_PASSWORD)
    assert _request(gate_home, "/api/sites", token=token).status == 200, (
        "no principal can reach the panel at all, so the assertion above is vacuous"
    )


def test_gate_panel_url_stops_advertising_the_run_token(gate_home):
    """G3: printing a URL carrying a credential that no longer works is a support
    ticket; printing one that still works is the G2 hole with a nicer interface.
    """
    import wpfy.panel as panel
    import wpfy.panel_auth as panel_auth

    config = panel.PanelConfig(host="127.0.0.1", port=gate_home.port, token=RUN_TOKEN)
    assert "#token=" in panel.panel_url(config), (
        "the ad-hoc run URL no longer carries a token, so `wpfy panel` on a fresh "
        "box cannot be opened"
    )

    panel_auth.add_user(ADMIN_USER, ADMIN_PASSWORD, role=panel_auth.ROLE_ADMIN)
    advertised = panel.panel_url(config)
    assert "#token=" not in advertised and RUN_TOKEN not in advertised, (
        f"the panel still advertises the run token once users exist: {advertised}"
    )


def test_gate_non_loopback_bind_is_still_refused(gate_home):
    """G4: exposure is Phase 7b and goes through Traefik. Nothing in the auth
    work is a reason to let the panel bind a public interface directly, and
    "we have logins now" is exactly the argument that would loosen this.
    """
    import wpfy.panel as panel

    for host in ("0.0.0.0", "10.0.0.5", "::"):
        with pytest.raises(ValueError):
            panel.make_panel_server(panel.PanelConfig(host=host, port=0, token=RUN_TOKEN))
