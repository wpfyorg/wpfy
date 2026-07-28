"""OPUS-OWNED IMMUTABLE GATE TESTS — Phase 2 (databases, PHP settings, vhost overrides).

DO NOT EDIT, SKIP, XFAIL, PARAMETRIZE AWAY, OR DELETE ANYTHING IN THIS FILE.

These tests are the security contract for Phase 2. They are written by the
orchestrator before implementation and are verified byte-identical (SHA-256
baseline) as a precondition for accepting the phase. If you believe a gate
asserts the wrong thing, escalate with evidence — do not edit the gate to make
your implementation pass.

This file is deliberately self-contained: it depends only on the stdlib and the
`wpfy` package, never on other test modules or shared fixtures, so that no edit
outside `src/wpfy/` can weaken it.

Invariants locked here:
  G1  A rejected SQL identifier never reaches the database container: it appears
      in no subprocess argv and no subprocess stdin, and the call is explicitly
      refused (ValueError, or a result with a non-zero exit_code) rather than
      silently no-oping.
  G2  Anti-vacuity for G1: a *valid* identifier does reach execution, so G1
      cannot pass by the whole module being inert.
  G3  The database root password never leaves the container: its value appears
      in no host argv, no subprocess stdin, no subprocess environment, and no
      returned message. Only the in-container shell expansion form
      (`-p"$MARIADB_ROOT_PASSWORD"`) is acceptable.
  G4  An nginx snippet that fails `nginx -t` never becomes live configuration:
      the previously live file is byte-identical afterwards, no leftover *.conf
      is left in the include directory, and no reload is issued.
  G5  Fail closed: when the container runtime cannot validate a snippet, the
      snippet is refused rather than installed unvalidated.
  G6  Anti-vacuity for G4/G5: the scaffold really does create the operator
      include file and really does wire it into the generated vhost, so a
      validated snippet is config nginx actually reads.
  G7  A per-site Adminer service is never published on a non-loopback address.
  G8  Untrusted PHP setting values cannot inject extra directives into the
      mounted php ini, and (anti-vacuity) a valid value does reach it.

Contract pinned by these gates (the actor must match these names):
  * module `wpfy.site_database` exposing `list_databases(domain)`,
    `list_users(domain)`, `create_database(domain, name)`,
    `drop_database(domain, name)`, `create_user(domain, user, password=...)`,
    `drop_user(domain, user)`, `set_user_password(domain, user, password=...)`,
    `grant(domain, user, database)`.
  * identifier whitelist exactly `^[a-z][a-z0-9_]{0,31}$`.
  * `wpfy.site_layout.set_nginx_custom(domain, content)`.
  * operator include file at `<site>/nginx/extra/custom.conf`, included by the
    generated vhost from directory `/etc/nginx/wpfy-extra`.
  * `SiteDefinition` field `adminer_port`.
  * rendered php overrides at `<site>/php/zz-wpfy.ini`.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import threading
import time
import urllib.error
import urllib.request
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path

import pytest

GATE_TOKEN = "gate-phase2-token"
SEEDED_DOMAIN = "seeded2.example"
ROOT_SECRET = "s3cr3t-gate-db-root-password"
USER_SECRET = "s3cr3t-gate-db-user-password"

# The whitelist this phase is contracted to enforce.
IDENTIFIER_PATTERN = re.compile(r"^[a-z][a-z0-9_]{0,31}$")


# --------------------------------------------------------------------------
# Self-contained harness (no shared fixtures by design)
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
    """Stands in for `subprocess.run` and records every host command.

    Every gate below asks the same question of this recorder: did a secret or a
    hostile identifier ever cross the process boundary? Returning a successful
    CompletedProcess by default also makes `docker_available()` report True
    without a real Docker install, so the runtime-dependent code paths are
    exercised instead of skipped.
    """

    def __init__(self) -> None:
        self.calls: list[dict] = []
        self.nginx_test_fails = False

    def reset(self) -> None:
        self.calls.clear()

    def __call__(self, args, **kwargs):
        argv = [str(item) for item in args] if isinstance(args, (list, tuple)) else [str(args)]
        stdin = kwargs.get("input")
        env = kwargs.get("env")
        self.calls.append({
            "argv": argv,
            "stdin": stdin if isinstance(stdin, str) else "",
            "cwd": str(kwargs.get("cwd") or ""),
            "env_values": list(env.values()) if isinstance(env, dict) else [],
        })
        if self.nginx_test_fails and _looks_like_nginx_test(argv):
            return subprocess.CompletedProcess(
                argv,
                1,
                "",
                'nginx: [emerg] unknown directive "wpfy_bogus_directive" in '
                "/etc/nginx/wpfy-extra/custom.conf:1\n"
                "nginx: configuration file /etc/nginx/nginx.conf test failed\n",
            )
        return subprocess.CompletedProcess(argv, 0, "", "")

    # -- queries -----------------------------------------------------------

    def mentions(self, needle: str) -> bool:
        """True if `needle` crossed the process boundary in any observable way."""
        for call in self.calls:
            if any(needle in item for item in call["argv"]):
                return True
            if needle in call["stdin"]:
                return True
            if any(needle in str(value) for value in call["env_values"]):
                return True
        return False

    def any_argv_contains(self, needle: str) -> bool:
        return any(needle in " ".join(call["argv"]) for call in self.calls)


def _looks_like_nginx_test(argv: list[str]) -> bool:
    joined = " ".join(argv)
    if "nginx" not in joined:
        return False
    return "-t" in argv or "nginx -t" in joined


@contextmanager
def _gate_home(tmp_path, monkeypatch, *, skip_runtime: bool):
    """Redirect wpfy's paths at an isolated home and stub the process boundary.

    Paths are redirected by mutating the shared frozen `settings.PATHS` singleton
    in place rather than by reloading modules. Every module in `src/wpfy`
    resolves paths through that object at call time, so in-place mutation reaches
    all of them. Reloading is deliberately avoided: `importlib.reload` reuses a
    module's __dict__, so symbols captured at import time by other test modules
    keep pointing at stale classes, silently breaking unrelated tests later in
    the same process, with no possible teardown.
    """
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
    if skip_runtime:
        os.environ["WPFY_SKIP_RUNTIME"] = "1"
    else:
        os.environ.pop("WPFY_SKIP_RUNTIME", None)
    for field in _PATH_FIELDS:
        object.__setattr__(paths, field, os.environ[f"WPFY_{field.upper()}"])
    wpfy.registry._REGISTRY = None          # singleton caches <state_dir>/sites.json

    recorder = _Recorder()
    import shutil as _shutil

    monkeypatch.setattr(subprocess, "run", recorder)
    monkeypatch.setattr(
        _shutil,
        "which",
        lambda name, *args, **kwargs: f"/usr/bin/{name}" if name == "docker" else None,
    )
    wpfy.site_runtime.docker_available.cache_clear()
    wpfy.site_runtime.docker_available()    # warm the cache so its probe is not recorded
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
    """Offline wpfy home with a live (stubbed) container runtime."""
    with _gate_home(tmp_path, monkeypatch, skip_runtime=False) as ctx:
        yield ctx


@pytest.fixture
def gate_panel(tmp_path, monkeypatch):
    """Offline wpfy home plus a real loopback panel server."""
    with _gate_home(tmp_path, monkeypatch, skip_runtime=True) as (paths, recorder):
        import wpfy.panel as panel

        config = panel.PanelConfig(host="127.0.0.1", port=0, token=GATE_TOKEN)
        server = panel.make_panel_server(config)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base_url = f"http://127.0.0.1:{server.server_address[1]}"
        try:
            yield base_url, paths, recorder
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)


def _seed_site(paths, domain: str = SEEDED_DOMAIN) -> Path:
    """Write a minimal but realistic site directory, including a root secret."""
    site = Path(paths.sites_dir) / domain
    (site / "nginx" / "extra").mkdir(parents=True, exist_ok=True)
    (site / "php").mkdir(parents=True, exist_ok=True)
    (site / "app").mkdir(parents=True, exist_ok=True)
    (site / ".env").write_text(
        f"DOMAIN={domain}\n"
        "SITE_FLAVOR=wp\n"
        "COMPOSE_PROJECT_NAME=seeded2-example\n"
        "APP_ROOT=/var/www/html\n"
        "PHP_VERSION=8.4\n"
        "SITE_UID=1500\n"
        "LETSENCRYPT_MODE=disabled\n"
        "DB_NAME=seeded2_example\n"
        "DB_USER=seeded2_example\n"
        f"DB_PASSWORD={USER_SECRET}\n"
        f"DB_ROOT_PASSWORD={ROOT_SECRET}\n",
        encoding="utf-8",
    )
    (site / "compose.yaml").write_text("services: {}\n", encoding="utf-8")
    (site / "nginx" / "default.conf").write_text("server {\n    listen 8080;\n}\n", encoding="utf-8")
    (site / "nginx" / "extra" / "custom.conf").write_text("", encoding="utf-8")
    return site


def _call(base_url, path, *, token=GATE_TOKEN, method="GET", body=None):
    request = urllib.request.Request(f"{base_url}{path}", method=method)
    if token is not None:
        request.add_header("Authorization", f"Bearer {token}")
    data = None
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        request.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(request, data=data, timeout=15) as response:
            return response.status, response.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8")


def _result_text(result) -> str:
    for attribute in ("message", "stderr", "stdout", "detail", "error"):
        value = getattr(result, attribute, None)
        if isinstance(value, str) and value:
            return value
    return repr(result)


def _refused(call) -> tuple[bool, str]:
    """Invoke `call`; report whether it was explicitly refused, and the text it produced.

    A refusal is either a raised ValueError or a returned result carrying a
    non-zero `exit_code`. A silent success with no effect is NOT a refusal — it
    would leave an operator believing a database was created.

    TypeError is deliberately not caught: a signature mismatch must surface as an
    error, never be mistaken for a rejected identifier.
    """
    try:
        result = call()
    except ValueError as exc:
        return True, str(exc)
    exit_code = getattr(result, "exit_code", None)
    if isinstance(exit_code, int) and exit_code != 0:
        return True, _result_text(result)
    return False, _result_text(result)


# --------------------------------------------------------------------------
# G1 / G2 — SQL identifier injection
# --------------------------------------------------------------------------

# Each entry builds the call for one identifier sink. `ident` is the untrusted
# identifier under test; every other argument is deliberately benign so that a
# failure can only be attributed to `ident`.
def _identifier_sinks(site_database, ident):
    return (
        ("create_database", lambda: site_database.create_database(SEEDED_DOMAIN, ident)),
        ("drop_database", lambda: site_database.drop_database(SEEDED_DOMAIN, ident)),
        ("create_user", lambda: site_database.create_user(SEEDED_DOMAIN, ident, password="Gate-Pass-1234")),
        ("drop_user", lambda: site_database.drop_user(SEEDED_DOMAIN, ident)),
        (
            "set_user_password",
            lambda: site_database.set_user_password(SEEDED_DOMAIN, ident, password="Gate-Pass-1234"),
        ),
        ("grant(user)", lambda: site_database.grant(SEEDED_DOMAIN, ident, "wp_gate_db")),
        ("grant(database)", lambda: site_database.grant(SEEDED_DOMAIN, "wp_gate_user", ident)),
    )


HOSTILE_IDENTIFIERS = (
    "wp; DROP DATABASE mysql",
    "wp`--",
    "wp'--",
    'wp"--',
    "wp\\",
    "wp\nDROP DATABASE mysql",
    "wp drop",
    "wp\tdrop",
    "wp$(id)",
    "wp%",
    "wp*",
    "wp-name",
    "mysql.user",
    "../../etc/passwd",
    "-wp",
    "1wp",
    "WPUPPER",
    "имя",
    "wp​drop",
    "",
    "a" * 33,
)


@pytest.mark.parametrize("ident", HOSTILE_IDENTIFIERS, ids=lambda value: repr(value)[:40])
def test_gate_hostile_sql_identifier_never_reaches_the_database(gate_home, ident):
    """G1: hostile identifiers are refused before any command crosses the boundary."""
    paths, recorder = gate_home
    _seed_site(paths)
    from wpfy import site_database

    assert not IDENTIFIER_PATTERN.match(ident), f"test payload {ident!r} is not actually hostile"

    for label, call in _identifier_sinks(site_database, ident):
        recorder.reset()
        refused, text = _refused(call)
        assert refused, f"{label} accepted hostile identifier {ident!r} (returned: {text})"
        if ident:
            assert not recorder.mentions(ident), (
                f"{label} leaked hostile identifier {ident!r} into a subprocess call: {recorder.calls}"
            )


# Names that satisfy the whitelist but must still be refused: granting a site user
# rights on any of these is a privilege-escalation path out of the site's own data.
# `mysql` is the decisive one — ALL PRIVILEGES there lets the grantee rewrite
# mysql.user and become root-equivalent for every database on the container.
SYSTEM_DATABASES = ("mysql", "information_schema", "performance_schema", "sys")


@pytest.mark.parametrize("name", SYSTEM_DATABASES)
def test_gate_system_databases_are_never_grantable_or_droppable(gate_home, name):
    """G1b: a whitelist-shaped system database name is still refused on every path.

    Added after review: the identifier whitelist alone does not stop
    `grant(user, "mysql")`, because "mysql" is a perfectly well-formed identifier.
    Every entry point that names a database must reject the system schemas.
    """
    paths, recorder = gate_home
    _seed_site(paths)
    from wpfy import site_database

    assert IDENTIFIER_PATTERN.match(name), f"{name!r} is whitelist-shaped by construction"

    sinks = (
        ("grant", lambda: site_database.grant(SEEDED_DOMAIN, "wp_gate_user", name)),
        ("create_database", lambda: site_database.create_database(SEEDED_DOMAIN, name)),
        ("drop_database", lambda: site_database.drop_database(SEEDED_DOMAIN, name)),
        (
            "create_user(grants)",
            lambda: site_database.create_user(
                SEEDED_DOMAIN, "wp_gate_user", password="Gate-Pass-1234", grants=[name],
            ),
        ),
    )
    for label, call in sinks:
        recorder.reset()
        refused, text = _refused(call)
        assert refused, f"{label} accepted system database {name!r} (returned: {text})"
        assert not recorder.mentions(name), (
            f"{label} sent system database {name!r} to the container: {recorder.calls}"
        )


def test_gate_db_failure_message_never_echoes_a_user_password(gate_home, monkeypatch):
    """G3b: a failing statement must not return the password it contained.

    Added after review: MariaDB quotes the offending SQL fragment back in syntax
    errors, so an unredacted stderr passthrough can hand a just-generated password
    to whatever renders the result — including the panel response body.
    """
    paths, recorder = gate_home
    _seed_site(paths)
    from wpfy import site_database

    leaked = "Leak-Me-9f3c2a"

    def _failing_run(args, **kwargs):
        recorder(args, **kwargs)
        stdin = kwargs.get("input") or ""
        return subprocess.CompletedProcess(
            list(args),
            1,
            "",
            f"ERROR 1064 (42000) at line 1: You have an error in your SQL syntax near {stdin.strip()!r}\n",
        )

    monkeypatch.setattr(subprocess, "run", _failing_run)

    for label, call in (
        ("create_user", lambda: site_database.create_user(SEEDED_DOMAIN, "wp_gate_user", password=leaked)),
        ("set_user_password", lambda: site_database.set_user_password(SEEDED_DOMAIN, "wp_gate_user", password=leaked)),
    ):
        recorder.reset()
        refused, text = _refused(call)
        assert refused, f"{label} reported success on a failing statement"
        assert leaked not in text, f"{label} echoed the user password back to the caller: {text!r}"


@pytest.mark.parametrize("ident", ("wp_extra", "a", "a" * 32, "wp2"))
def test_gate_valid_sql_identifier_reaches_execution(gate_home, ident):
    """G2: anti-vacuity — valid identifiers really do get executed.

    Without this, every G1 assertion would pass trivially if the module simply
    refused everything or never shelled out at all.
    """
    paths, recorder = gate_home
    _seed_site(paths)
    from wpfy import site_database

    assert IDENTIFIER_PATTERN.match(ident), f"test payload {ident!r} should be valid"

    recorder.reset()
    result = site_database.create_database(SEEDED_DOMAIN, ident)
    exit_code = getattr(result, "exit_code", 0)
    assert exit_code == 0, f"create_database rejected the valid identifier {ident!r}: {_result_text(result)}"
    assert recorder.mentions(ident), (
        f"create_database({ident!r}) never reached the container; "
        f"the identifier gates would pass vacuously. Calls: {recorder.calls}"
    )


# --------------------------------------------------------------------------
# G3 — the database root password never leaves the container
# --------------------------------------------------------------------------

def test_gate_db_root_password_never_crosses_the_process_boundary(gate_home):
    """G3: the root password value is never visible to the host process table.

    The contracted pattern is `sh -lc '... -p"$MARIADB_ROOT_PASSWORD"'`, expanded
    by the shell *inside* the db container, exactly as `backup_site` already
    does. Any implementation that reads DB_ROOT_PASSWORD from .env and passes the
    value on the command line, on stdin, or via the child environment fails here.
    """
    paths, recorder = gate_home
    _seed_site(paths)
    from wpfy import site_database

    operations = (
        ("list_databases", lambda: site_database.list_databases(SEEDED_DOMAIN)),
        ("list_users", lambda: site_database.list_users(SEEDED_DOMAIN)),
        ("create_database", lambda: site_database.create_database(SEEDED_DOMAIN, "wp_gate_db")),
        ("drop_database", lambda: site_database.drop_database(SEEDED_DOMAIN, "wp_gate_db")),
        (
            "create_user",
            lambda: site_database.create_user(SEEDED_DOMAIN, "wp_gate_user", password="Gate-Pass-1234"),
        ),
        ("drop_user", lambda: site_database.drop_user(SEEDED_DOMAIN, "wp_gate_user")),
        ("grant", lambda: site_database.grant(SEEDED_DOMAIN, "wp_gate_user", "wp_gate_db")),
    )

    for label, call in operations:
        recorder.reset()
        result = call()
        for index, recorded in enumerate(recorder.calls):
            assert not any(ROOT_SECRET in item for item in recorded["argv"]), (
                f"{label}: root password appeared in host argv of call {index}: {recorded['argv']}"
            )
            assert ROOT_SECRET not in recorded["stdin"], (
                f"{label}: root password appeared on subprocess stdin of call {index}"
            )
            assert not any(ROOT_SECRET in str(value) for value in recorded["env_values"]), (
                f"{label}: root password appeared in the child environment of call {index}"
            )
        assert ROOT_SECRET not in _result_text(result), f"{label}: root password leaked into the result"


def test_gate_generated_db_user_password_never_appears_in_host_argv(gate_home):
    """G3: a generated user password is delivered the same secret-safe way.

    The password the operator is shown once must still not be observable in the
    host process table while it is being applied.
    """
    paths, recorder = gate_home
    _seed_site(paths)
    from wpfy import site_database

    recorder.reset()
    result = site_database.create_user(SEEDED_DOMAIN, "wp_gate_user", password=USER_SECRET)
    assert getattr(result, "exit_code", 0) == 0, f"create_user failed: {_result_text(result)}"

    for index, recorded in enumerate(recorder.calls):
        assert not any(USER_SECRET in item for item in recorded["argv"]), (
            f"user password appeared in host argv of call {index}: {recorded['argv']}"
        )
        assert not any(USER_SECRET in str(value) for value in recorded["env_values"]), (
            f"user password appeared in the child environment of call {index}"
        )


# --------------------------------------------------------------------------
# G4 / G5 / G6 — custom nginx snippets are validated before they go live
# --------------------------------------------------------------------------

GOOD_SNIPPET = "location = /gate-ok.txt {\n    return 204;\n}\n"
BAD_SNIPPET = "wpfy_bogus_directive on;\n"
PREEXISTING_SNIPPET = "location = /gate-existing.txt {\n    return 204;\n}\n"


def _extra_dir(paths, domain: str = SEEDED_DOMAIN) -> Path:
    return Path(paths.sites_dir) / domain / "nginx" / "extra"


def test_gate_invalid_nginx_snippet_never_becomes_live_config(gate_home):
    """G4: a snippet that fails `nginx -t` leaves the live config untouched."""
    paths, recorder = gate_home
    _seed_site(paths)
    from wpfy import site_layout

    live = _extra_dir(paths) / "custom.conf"
    live.write_text(PREEXISTING_SNIPPET, encoding="utf-8")
    before = live.read_bytes()
    before_listing = sorted(path.name for path in _extra_dir(paths).iterdir())

    recorder.reset()
    recorder.nginx_test_fails = True
    refused, text = _refused(lambda: site_layout.set_nginx_custom(SEEDED_DOMAIN, BAD_SNIPPET))

    assert refused, "set_nginx_custom accepted a snippet that fails nginx -t"
    assert live.read_bytes() == before, "the live custom.conf was modified despite failed validation"
    assert sorted(path.name for path in _extra_dir(paths).iterdir()) == before_listing, (
        "validation left a stray file in the include directory; "
        f"nginx includes *.conf from there. Listing: {sorted(p.name for p in _extra_dir(paths).iterdir())}"
    )
    assert not recorder.any_argv_contains("reload"), (
        f"nginx was reloaded even though validation failed: {recorder.calls}"
    )
    assert "nginx" in text.lower(), f"the nginx -t error text was not reported back to the caller: {text!r}"


def test_gate_valid_nginx_snippet_is_validated_then_applied(gate_home):
    """G4 anti-vacuity: a good snippet is validated by nginx -t and then goes live."""
    paths, recorder = gate_home
    _seed_site(paths)
    from wpfy import site_layout

    live = _extra_dir(paths) / "custom.conf"
    live.write_text(PREEXISTING_SNIPPET, encoding="utf-8")

    recorder.reset()
    recorder.nginx_test_fails = False
    result = site_layout.set_nginx_custom(SEEDED_DOMAIN, GOOD_SNIPPET)

    assert getattr(result, "exit_code", 0) == 0, f"a valid snippet was refused: {_result_text(result)}"
    assert live.read_text(encoding="utf-8") == GOOD_SNIPPET, "the validated snippet did not become live"
    assert any(_looks_like_nginx_test(call["argv"]) for call in recorder.calls), (
        f"the snippet was installed without ever running nginx -t: {recorder.calls}"
    )
    assert sorted(path.name for path in _extra_dir(paths).iterdir()) == ["custom.conf"], (
        "a temporary file was left behind in the include directory after a successful write"
    )


def test_gate_nginx_snippet_refused_when_runtime_cannot_validate(gate_home, monkeypatch):
    """G5: no container runtime means no validation, which means no install."""
    paths, recorder = gate_home
    _seed_site(paths)
    import shutil as _shutil

    import wpfy.site_runtime
    from wpfy import site_layout

    live = _extra_dir(paths) / "custom.conf"
    live.write_text(PREEXISTING_SNIPPET, encoding="utf-8")
    before = live.read_bytes()

    monkeypatch.setattr(_shutil, "which", lambda name, *args, **kwargs: None)
    wpfy.site_runtime.docker_available.cache_clear()
    recorder.reset()

    refused, _text = _refused(lambda: site_layout.set_nginx_custom(SEEDED_DOMAIN, GOOD_SNIPPET))

    assert refused, "an unvalidated snippet was accepted while the runtime was unavailable"
    assert live.read_bytes() == before, "an unvalidated snippet was written to the live config"
    assert sorted(path.name for path in _extra_dir(paths).iterdir()) == ["custom.conf"], (
        "a stray file was left in the include directory when validation was impossible"
    )


def test_gate_scaffold_creates_and_wires_the_operator_include(gate_home):
    """G6: the include file exists and the generated vhost actually reads it.

    Without this, a perfectly validated snippet could be written to a file nginx
    never loads, and every gate above would still pass.
    """
    paths, _recorder = gate_home
    from wpfy import site_layout
    from wpfy.site_definition import SiteDefinition

    domain = "wired.example"
    spec = SiteDefinition(domain=domain, flavor="wp", use_mysql=True, use_redis=False)
    site_layout.ensure_site_scaffold(spec)

    site = Path(paths.sites_dir) / domain
    include_file = site / "nginx" / "extra" / "custom.conf"
    assert include_file.exists(), "ensure_site_scaffold did not create nginx/extra/custom.conf"

    vhost = (site / "nginx" / "default.conf").read_text(encoding="utf-8")
    assert "wpfy-extra" in vhost, f"the generated vhost does not include the operator directory:\n{vhost}"

    compose = (site / "compose.yaml").read_text(encoding="utf-8")
    assert "/etc/nginx/wpfy-extra" in compose, (
        f"the operator include directory is not mounted into the web container:\n{compose}"
    )

    operator_content = "# operator owned\n"
    include_file.write_text(operator_content, encoding="utf-8")
    site_layout.ensure_site_scaffold(spec)
    assert include_file.read_text(encoding="utf-8") == operator_content, (
        "ensure_site_scaffold overwrote the operator-owned include file"
    )

    php_custom = site / "php" / "custom.ini"
    assert php_custom.exists(), "ensure_site_scaffold did not create php/custom.ini"
    php_operator = "; operator owned\n"
    php_custom.write_text(php_operator, encoding="utf-8")
    site_layout.ensure_site_scaffold(spec)
    assert php_custom.read_text(encoding="utf-8") == php_operator, (
        "ensure_site_scaffold overwrote the operator-owned php/custom.ini"
    )


# --------------------------------------------------------------------------
# G7 — Adminer is never exposed beyond loopback
# --------------------------------------------------------------------------

def test_gate_adminer_is_published_on_loopback_only(gate_home):
    """G7: every published Adminer port binds 127.0.0.1, never a public address."""
    _paths, _recorder = gate_home
    from wpfy import site_layout
    from wpfy.site_definition import SiteDefinition

    spec = SiteDefinition(
        domain="adminer.example",
        flavor="wp",
        use_mysql=True,
        use_redis=False,
        site_uid=1500,
    )
    spec = replace(spec, adminer_port="8081")
    compose = site_layout.compose_content(spec)

    assert "adminer" in compose, "adminer_port was set but no adminer service was emitted"

    published = [
        line.strip()
        for line in compose.splitlines()
        if line.strip().startswith("- ") and ":" in line and "8081" in line
    ]
    assert published, f"the adminer service published no port mapping:\n{compose}"
    for line in published:
        assert "127.0.0.1:" in line, f"adminer port is not bound to loopback: {line}"
        assert "0.0.0.0" not in line, f"adminer port is bound to all interfaces: {line}"


# --------------------------------------------------------------------------
# G8 — untrusted PHP setting values cannot inject ini directives
# --------------------------------------------------------------------------

PHP_INJECTION_VALUES = (
    "256M\ndisable_functions =",
    "256M\nopen_basedir = none",
    "256M\n[PHP]\nallow_url_include = On",
    "256M\r\nauto_prepend_file = /var/www/html/shell.php",
    "256M; extension=evil.so",
    "256M\x00",
)

_PHP_SETTING_ROUTES = ("php-settings", "config")


def _php_ini_text(paths, domain: str = SEEDED_DOMAIN) -> str:
    ini = Path(paths.sites_dir) / domain / "php" / "zz-wpfy.ini"
    return ini.read_text(encoding="utf-8") if ini.exists() else ""


@pytest.mark.parametrize("value", PHP_INJECTION_VALUES, ids=lambda value: repr(value)[:40])
def test_gate_php_setting_injection_never_reaches_the_mounted_ini(gate_panel, value):
    """G8: a hostile memory-limit value never lands in the mounted php ini.

    Both candidate routes are exercised and their status codes are not asserted
    on: what matters is the outcome on disk, so this gate stays honest whichever
    route the actor wires up.
    """
    base_url, paths, _recorder = gate_panel
    _seed_site(paths)

    before = _php_ini_text(paths)
    for route in _PHP_SETTING_ROUTES:
        _call(
            base_url,
            f"/api/sites/{SEEDED_DOMAIN}/{route}",
            method="POST",
            body={"php_memory_limit": value},
        )

    after = _php_ini_text(paths)
    injected = after[len(before):] if after.startswith(before) else after
    for marker in ("disable_functions", "open_basedir", "allow_url_include", "auto_prepend_file", "extension="):
        assert marker not in after, f"injected directive {marker!r} reached php/zz-wpfy.ini:\n{after}"
    assert "\x00" not in after, "a NUL byte reached php/zz-wpfy.ini"
    assert "[PHP]" not in injected, "an injected ini section header reached php/zz-wpfy.ini"


def test_gate_valid_php_setting_reaches_the_mounted_ini(gate_panel):
    """G8 anti-vacuity: a legitimate value really is applied through the panel."""
    base_url, paths, _recorder = gate_panel
    _seed_site(paths)

    statuses = {}
    for route in _PHP_SETTING_ROUTES:
        status, body = _call(
            base_url,
            f"/api/sites/{SEEDED_DOMAIN}/{route}",
            method="POST",
            body={"php_memory_limit": "512M"},
        )
        statuses[route] = (status, body)

    assert any(200 <= status < 300 for status, _ in statuses.values()), (
        f"no panel route accepted a valid php_memory_limit: {statuses}"
    )

    deadline = time.monotonic() + 10.0
    ini = ""
    while time.monotonic() < deadline:
        ini = _php_ini_text(paths)
        if "512M" in ini:
            break
        time.sleep(0.1)

    assert "memory_limit" in ini and "512M" in ini, (
        f"a valid php_memory_limit never reached php/zz-wpfy.ini; the injection gate "
        f"would pass vacuously. Responses: {statuses}. Ini:\n{ini!r}"
    )
