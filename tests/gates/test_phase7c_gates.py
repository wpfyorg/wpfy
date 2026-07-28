"""OPUS-OWNED IMMUTABLE GATE TESTS — Phase 7c (panel login and user-management UI).

DO NOT EDIT, SKIP, XFAIL, PARAMETRIZE AWAY, OR DELETE ANYTHING IN THIS FILE.

These tests are the security and correctness contract for Phase 7c. They are
written by the orchestrator before implementation and are verified byte-identical
(SHA-256 baseline) as a precondition for accepting the phase. If you believe a
gate asserts the wrong thing, escalate with evidence — do not edit the gate.

This file is deliberately self-contained: it depends only on the stdlib and the
`wpfy` package, never on other test modules or shared fixtures.

There is no browser here, so these gates assert two things a browser could not
tell you anyway: what the shipped assets contain, and what the server does. The
actual rendering is verified by the actor's own browser cycle, the way every
previous UI phase in this project was.

What this phase can get wrong that nothing else catches:

    The UI is the one component that *holds a live credential in memory* and is
    also the one component built out of attacker-adjacent material — a site's
    own filenames, domains, and log lines all get rendered into it. Phases 1
    through 7b made the API safe. This phase can undo that without touching a
    single API route.

    1. **Role-filtered navigation is a convenience, never a boundary.** Hiding a
       menu item is presentation. If any part of this phase reasons "the button
       is hidden, so the check can be relaxed", the entire role system built in
       7a becomes decorative. The API must keep refusing regardless of what the
       UI draws, and this file re-asserts that from the outside.
    2. **The Content-Security-Policy is the only thing bounding what an XSS can
       do with the session token**, and a login form is exactly the kind of new
       markup that tempts an inline handler or an inline `<script>`. Adding
       `'unsafe-inline'` to make a form work would trade the one control that
       makes bearer-token-in-sessionStorage an acceptable design.
    3. **The static assets are served without credentials and must be** — you
       cannot fetch a login page with a token you do not have yet. That makes
       them the one part of the panel an unauthenticated stranger always reads,
       so anything baked into them is public.
    4. **The `#token=` fragment path must die exactly when users do.** A fresh
       box needs it; a box with accounts must not honour it. Getting the
       condition backwards either bricks first-run or leaves a bypass.

Invariants locked here:
  U1   A login form exists and authenticates through `/api/auth/login`.
  U2   The login form collects a second factor.
  U3   The CSP is not weakened: no `unsafe-inline`, no `unsafe-eval`,
       `default-src 'self'`, `frame-ancestors 'none'`.
  U4   No inline event handler or inline script logic in the markup.
  U5   Static assets are reachable with no credentials — anti-vacuity for U6.
  U6   Static assets contain no token, hash, salt, or TOTP secret.
  U7   The static handler still refuses to serve anything outside its root.
  U8   The session credential is not persisted to `localStorage`.
  U9   Logout clears the client-side credential as well as calling the API.
  U10  A user-management view exists and talks to `/api/users`.
  U11  The UI reads its own role from `/api/auth/me` rather than inferring it.
  U12  Hiding navigation is not the boundary: the API still refuses a
       site-manager whatever the UI renders.
  U13  Anti-vacuity for U12: the same request succeeds for an admin.
  U14  The run-token fragment path is honoured only while no user exists.

Eight of these fourteen pass *before* this phase is implemented, and that is
deliberate rather than sloppy — verified individually against the tree as it
stood when the file was written:

  U3, U4, U5, U6, U7, U8   properties the shipped panel already has. This phase
                           adds a login form, a user-management view, and
                           role-aware navigation to the same three files. Every
                           one of these is a property that a new form, a new
                           fetch, or a relaxed policy would quietly remove. They
                           exist to fail *later*, not now.
  U12, U13                 the API-side role boundary, established by 7a and
                           re-asserted here from outside the browser. If this
                           phase ever makes the UI the boundary, U12 is what
                           notices.

The six that fail today — U1, U2, U9, U10, U11, U14 — are this phase's actual
work.

Contract pinned by these gates:

  The panel's static assets stay exactly three files under
  `src/wpfy/panel_static/`: `index.html`, `panel.css`, `panel.js`. No build
  step, no bundler, no dependency — the panel is served by `http.server` from
  disk and that is not changing in this phase.

  `GET /` serves `index.html` unauthenticated. Everything under `/api/` keeps
  the behaviour Phases 1-7b established.
"""

from __future__ import annotations

import json
import re
import threading
import http.client
import os
from pathlib import Path

import pytest

GATE_TOKEN = "phase7c-run-token"
ADMIN_USER = "gate-ui-admin"
ADMIN_PASSWORD = "PH7C-admin-pw-2b74de"
MANAGER_USER = "gate-ui-manager"
MANAGER_PASSWORD = "PH7C-manager-pw-8fa10c"
ASSIGNED_DOMAIN = "ui-assigned.example"
OTHER_DOMAIN = "ui-other.example"
SITE_UID = 1811

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

TRAVERSAL_TARGETS = (
    "/../panel.py",
    "/../../settings.py",
    "/%2e%2e/panel.py",
    "/....//panel.py",
    "/../../../../../../etc/passwd",
    "/./../panel.py",
)


class Response:
    def __init__(self, status: int, body: bytes, headers: list[tuple[str, str]]):
        self.status = status
        self.body = body
        self.headers = headers

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", "replace")

    def header(self, name: str) -> str | None:
        for key, value in self.headers:
            if key.lower() == name.lower():
                return value
        return None

    def json(self) -> dict:
        return json.loads(self.text)


def _static_dir() -> Path:
    import wpfy.panel as panel

    return Path(panel.STATIC_DIR)


def _asset(name: str) -> str:
    return (_static_dir() / name).read_text(encoding="utf-8", errors="replace")


def _all_assets() -> str:
    return "\n".join(_asset(path.name) for path in sorted(_static_dir().iterdir())
                     if path.is_file())


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
        "DB_NAME=uidb\nDB_USER=uidb\nDB_PASSWORD=PH7C-db-secret\n",
        encoding="utf-8",
    )
    (site / "compose.yaml").write_text("services: {}\n", encoding="utf-8")
    (site / "nginx" / "default.conf").write_text("server {\n    listen 8080;\n}\n", encoding="utf-8")
    return site


@pytest.fixture
def gate_home(tmp_path):
    """Isolated home with a live loopback panel and no users yet.

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
        "WPFY_SKIP_WORDPRESS_DOWNLOAD": "1",
        "WPFY_SKIP_CHOWN": "1",
    })
    for field in _PATH_FIELDS:
        object.__setattr__(paths, field, os.environ[f"WPFY_{field.upper()}"])
    for directory in (paths.state_dir, paths.log_dir, paths.config_dir):
        Path(directory).mkdir(parents=True, exist_ok=True)

    wpfy.registry._REGISTRY = None
    _seed_site(paths, ASSIGNED_DOMAIN, uid=SITE_UID)
    _seed_site(paths, OTHER_DOMAIN, uid=SITE_UID + 1)

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


def _request(home, path, *, method="GET", token=None, body=None) -> Response:
    connection = http.client.HTTPConnection(home.host, home.port, timeout=30)
    try:
        headers = {}
        if token is not None:
            headers["Authorization"] = f"Bearer {token}"
        payload = None
        if body is not None:
            payload = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        connection.request(method, path, body=payload, headers=headers)
        response = connection.getresponse()
        return Response(response.status, response.read(), response.getheaders())
    finally:
        connection.close()


def _seed_users():
    import wpfy.panel_auth as panel_auth

    panel_auth.add_user(ADMIN_USER, ADMIN_PASSWORD, role=panel_auth.ROLE_ADMIN)
    panel_auth.add_user(MANAGER_USER, MANAGER_PASSWORD,
                        role=panel_auth.ROLE_SITE_MANAGER, sites=(ASSIGNED_DOMAIN,))


def _login(home, username, password) -> str:
    response = _request(home, "/api/auth/login", method="POST",
                        body={"username": username, "password": password})
    assert response.status == 200, f"login failed for {username}: {response.text}"
    return response.json()["token"]


# ---------------------------------------------------------------------------
# U1-U2 — the login screen
# ---------------------------------------------------------------------------

def test_gate_a_login_form_authenticates_through_the_api(gate_home):
    """U1: anti-vacuity floor for the whole file. Without a login form the panel
    is unusable the moment a user exists, because 7a retires the run token.
    """
    assets = _all_assets()
    assert "/api/auth/login" in assets, (
        "no shipped asset calls the login endpoint, so there is no way into a "
        "panel that has users"
    )
    for field in ("username", "password"):
        assert field in assets.lower(), f"the login form collects no {field}"


def test_gate_the_login_form_collects_a_second_factor(gate_home):
    """U2: 7a makes TOTP mandatory before the panel may be exposed, and 7b
    refuses exposure without it. A UI with no TOTP field makes both unreachable
    for anyone who does not use the CLI.
    """
    assets = _all_assets().lower()
    assert "totp" in assets, "the login form has no second-factor field"


# ---------------------------------------------------------------------------
# U3-U4 — the policy that bounds an XSS
# ---------------------------------------------------------------------------

def test_gate_the_content_security_policy_is_not_weakened(gate_home):
    """U3: sessionStorage holding a bearer token is only an acceptable design
    while the CSP forbids injected script. A login form is exactly the markup
    that tempts `'unsafe-inline'`, and that one word would trade the control
    that makes the whole storage decision defensible.
    """
    response = _request(gate_home, "/")
    policy = response.header("Content-Security-Policy")
    assert policy, f"index.html is served with no CSP: {dict(response.headers)}"

    assert "default-src 'self'" in policy, f"CSP no longer defaults to self: {policy}"
    assert "frame-ancestors 'none'" in policy, f"CSP allows framing: {policy}"
    for forbidden in ("unsafe-inline", "unsafe-eval", "data: script", "*"):
        assert forbidden not in policy, f"CSP weakened with {forbidden!r}: {policy}"
    assert response.header("X-Content-Type-Options") == "nosniff"


def test_gate_no_inline_handlers_or_inline_script_logic(gate_home):
    """U4: the companion to U3. A CSP without `'unsafe-inline'` and markup that
    needs it produces a page that silently does nothing — so the pressure is
    always to relax the policy rather than fix the markup.
    """
    markup = _asset("index.html")
    handlers = re.findall(r"\son[a-z]+\s*=\s*[\"']", markup, re.IGNORECASE)
    assert not handlers, f"inline event handlers in index.html: {handlers[:5]}"

    inline_scripts = re.findall(r"<script(?![^>]*\ssrc=)[^>]*>(.*?)</script>",
                                markup, re.DOTALL | re.IGNORECASE)
    substantive = [body for body in inline_scripts if body.strip()]
    assert not substantive, (
        f"index.html carries {len(substantive)} inline script block(s), which "
        "cannot execute under this CSP"
    )


# ---------------------------------------------------------------------------
# U5-U7 — the assets a stranger can always read
# ---------------------------------------------------------------------------

def test_gate_static_assets_are_reachable_without_credentials(gate_home):
    """U5: anti-vacuity for U6, and a requirement in its own right — you cannot
    fetch a login page with a token you do not have yet.
    """
    _seed_users()
    for path in ("/", "/index.html", "/panel.js", "/panel.css"):
        response = _request(gate_home, path)
        assert response.status == 200, (
            f"{path} is not reachable without credentials ({response.status}), "
            "so the login screen can never load"
        )


def test_gate_static_assets_carry_no_credential(gate_home):
    """U6: these three files are the one part of the panel an unauthenticated
    stranger always reads. Anything baked into them is published.
    """
    import wpfy.panel_auth as panel_auth

    _seed_users()
    secret_b32, _ = panel_auth.enable_totp(ADMIN_USER)
    record = next(entry for entry in json.loads(
        panel_auth.users_path().read_text(encoding="utf-8"))["users"]
        if entry["username"] == ADMIN_USER)
    session = _login(gate_home, MANAGER_USER, MANAGER_PASSWORD)

    markers = {
        "run token": GATE_TOKEN,
        "session token": session,
        "password hash": record["password_hash"],
        "password salt": record["password_salt"],
        "totp secret": secret_b32,
        "admin password": ADMIN_PASSWORD,
    }
    leaks = []
    for path in ("/index.html", "/panel.js", "/panel.css"):
        body = _request(gate_home, path).text
        for label, value in markers.items():
            if value and value in body:
                leaks.append(f"{path} discloses the {label}")
    assert not leaks, "static assets carry credentials:\n  " + "\n  ".join(leaks)


def test_gate_the_static_handler_serves_nothing_outside_its_root(gate_home):
    """U7: a regression guard on behaviour Phase 1 shipped. This phase adds
    markup and routes around the same handler, which is when a path join gets
    rewritten by someone who did not know why it looked like that.
    """
    for target in TRAVERSAL_TARGETS:
        response = _request(gate_home, target)
        assert response.status != 200 or "def " not in response.text, (
            f"{target} served source from outside the static root"
        )
        assert "PH7C" not in response.text
        assert "DB_PASSWORD" not in response.text


# ---------------------------------------------------------------------------
# U8-U9 — the credential the browser holds
# ---------------------------------------------------------------------------

def test_gate_the_session_credential_is_not_persisted_to_localstorage(gate_home):
    """U8: a regression guard — the shipped panel already uses sessionStorage,
    and that is the right choice. `localStorage` survives a browser restart and
    is shared across every tab of the origin, so a token stolen once stays
    useful until it expires rather than until the tab closes.
    """
    script = _asset("panel.js")
    offenders = re.findall(r"localStorage\s*\.\s*(setItem|getItem)\s*\(([^)]*)\)", script)
    assert not offenders, (
        f"panel.js reaches for localStorage: {offenders[:3]} — the session "
        "credential must not outlive the tab"
    )
    assert "sessionStorage" in script, "panel.js no longer uses sessionStorage at all"


def test_gate_logout_clears_the_client_credential(gate_home):
    """U9: calling the logout endpoint without clearing the stored token leaves
    a dead credential in the tab and a live-looking UI. Clearing the token
    without calling the endpoint leaves a live credential on the server. Both
    are required.
    """
    script = _asset("panel.js")
    assert "/api/auth/logout" in script, "panel.js never calls the logout endpoint"
    assert re.search(r"sessionStorage\s*\.\s*removeItem", script), (
        "panel.js never clears the stored session credential"
    )


# ---------------------------------------------------------------------------
# U10-U13 — roles in the UI, and the boundary that is not the UI
# ---------------------------------------------------------------------------

def test_gate_a_user_management_view_exists(gate_home):
    """U10: without it, every account operation is CLI-only and the panel cannot
    be handed to anyone who is not on the box.
    """
    assets = _all_assets()
    assert "/api/users" in assets, "no shipped asset talks to the user-management API"


def test_gate_the_ui_reads_its_role_from_the_server(gate_home):
    """U11: a UI that infers its role from which requests happened to succeed
    renders differently depending on failures, and a UI that stores the role
    from the login response alone never notices it being changed underneath it.
    """
    assets = _all_assets()
    assert "/api/auth/me" in assets, (
        "the UI never asks the server who it is, so its navigation is guesswork"
    )


def test_gate_hidden_navigation_is_not_the_boundary(gate_home):
    """U12: the gate that keeps this phase honest.

    Everything else in this file is about what gets drawn. This one steps
    outside the browser entirely and re-asserts that the API refuses a
    site-manager whatever the UI chose to render — because the day someone
    reasons "the button is hidden, so the check can be relaxed" is the day 7a's
    entire role system becomes decoration.
    """
    _seed_users()
    manager = _login(gate_home, MANAGER_USER, MANAGER_PASSWORD)

    refused = (
        ("GET", "/api/users", None),
        ("POST", "/api/users", {"username": "x", "password": "y", "role": "admin"}),
        ("GET", "/api/overview", None),
        ("GET", "/api/system/services", None),
        ("GET", f"/api/sites/{OTHER_DOMAIN}", None),
        ("GET", f"/api/sites/{OTHER_DOMAIN}/files?path=.", None),
    )
    for method, path, body in refused:
        response = _request(gate_home, path, method=method, token=manager, body=body)
        assert response.status == 403, (
            f"{method} {path} returned {response.status} for a site-manager; the "
            "UI hiding it is not a boundary"
        )
        assert "PH7C-db-secret" not in response.text


def test_gate_an_admin_reaches_what_the_manager_cannot(gate_home):
    """U13: anti-vacuity for U12 — every assertion above passes against a panel
    that answers 403 to everyone, including a panel whose UI cannot log in.
    """
    _seed_users()
    admin = _login(gate_home, ADMIN_USER, ADMIN_PASSWORD)

    for path in ("/api/users", "/api/overview", f"/api/sites/{OTHER_DOMAIN}"):
        response = _request(gate_home, path, token=admin)
        assert response.status == 200, (
            f"an admin was refused {path} ({response.status}), so the refusals "
            "above prove nothing about roles"
        )


def test_gate_the_run_token_fragment_dies_with_the_first_user(gate_home):
    """U14: a fresh box has no accounts and must still open from the printed
    URL; a box with accounts must not honour it. Getting the condition backwards
    either bricks first-run or leaves the bypass 7a's G2 exists to close.
    """
    import wpfy.panel as panel
    import wpfy.panel_auth as panel_auth

    config = panel.PanelConfig(host="127.0.0.1", port=gate_home.port, token=GATE_TOKEN)
    assert "#token=" in panel.panel_url(config), "a fresh panel prints no usable URL"
    assert _request(gate_home, "/api/sites", token=GATE_TOKEN).status == 200

    _seed_users()
    assert "#token=" not in panel.panel_url(config), (
        "the panel still advertises the run token once users exist"
    )
    assert _request(gate_home, "/api/sites", token=GATE_TOKEN).status == 401, (
        "the run token still authenticates after a user was created"
    )

    script = _asset("panel.js")
    assert "auth/login" in script, (
        "panel.js has no login path, so a panel with users cannot be opened at all"
    )
