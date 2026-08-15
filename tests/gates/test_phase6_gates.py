"""GATE TESTS — Phase 6 (native path-jailed file manager).

These tests are the security and correctness contract for Phase 6. They were
written before the implementation and encode decisions, not implementation
details, so a gate failing usually means the product regressed rather than that
the gate is out of date.

They are editable, and were immutable until 2026-08-15. Change one only when
the decision it pins has genuinely changed, never to make a red test green:
say in the commit which decision moved and why, and keep the gate asserting the
new one. A gate deleted or weakened to pass takes its invariant with it.

This file is deliberately self-contained: it depends only on the stdlib and the
`wpfy` package, never on other test modules or shared fixtures.

Deliberately NOT re-tested here: bearer auth on the new routes, and the
`mutates=True` declaration. Phase 3b's G1/G2 derive the mutating-route list from
the panel's own route table, and Phase 5b's R1 asserts every non-GET route
declares itself — both therefore already cover every route this phase adds.

What this phase can get wrong that nothing else catches:

    Every earlier phase accepted a *vocabulary*: a flavor, a service name, a
    cache mode, a scope. The set of legal values was finite and could be
    whitelisted. Phase 6 is the first phase to accept an *arbitrary path* from
    the operator and hand it to the filesystem, and the filesystem is not a
    vocabulary — it is a graph with edges (symlinks) that the site's own
    unprivileged users can add at any time, from SFTP or from PHP, without
    wpfy's knowledge.

    That inverts the trust model of every gate written so far. Earlier gates
    ask "is this input in the allowed set?". These gates ask "does this input,
    plus a filesystem an attacker has partially authored, still land inside
    `app/`?" — and the answer has to stay yes for inputs nobody enumerated.

    Four specific things go wrong here and nowhere else:

    1. `.env` sits one directory above the jail root. It holds DB_PASSWORD,
       DB_ROOT_PASSWORD and the SFTP password. `../.env` is not an exotic
       payload; it is the first thing anyone types. `db-data/` and
       `compose.yaml` are its neighbours.
    2. A `realpath` containment check *looks* correct and passes most of these
       gates, because resolving a symlink to `/etc/passwd` does leave the jail
       and does get caught. What it does not catch is the swap between the
       check and the open. The locked design is an lstat walk that refuses a
       symlink component outright, and the only way to test that the walk
       exists — rather than a containment check that happens to agree — is a
       symlink whose target is *inside* the jail. Gate J7 is that test, and it
       is the one gate a plausible wrong implementation fails.
    3. The panel serves the jail's contents back over its own origin, where the
       operator's bearer token lives. A site's `app/` directory is full of
       attacker-influenced files: an uploaded `.html`, a plugin's `.svg`, a
       comment-injected `.js`. Serving any of them with a guessable content
       type is stored XSS against the panel itself.
    4. wpfy runs as root. A file it creates in the web root is root-owned, and
       a root-owned file in `wp-content` is the project's oldest documented
       footgun — it silently breaks the site's own updater and every later
       wp-cli run.

Invariants locked here:
  J1   Every file operation refuses a traversal, absolute, or NUL-bearing path.
  J2   Anti-vacuity for J1: every operation works on a legitimate nested path.
  J3   No hostile path — including percent-encoded forms that J1 does not
       require to be *refused* — changes or reveals anything outside the jail.
  J4   A symlink whose target escapes the jail is never read, written, or
       followed, and its target's bytes are never returned.
  J5   A symlink whose target is *inside* the jail is still not traversed. This
       separates an lstat component walk from a realpath containment check.
  J6   Listing a directory containing symlinks succeeds and reports them as
       symlinks without following them.
  J7   The site's `.env`, `compose.yaml` and `db-data/` are unreachable by any
       path form, and no file response ever contains a site secret.
  J8   One site's file routes never reach another site's files.
  D1   Every download is `application/octet-stream` + `attachment` + `nosniff`,
       whatever the file's extension.
  D2   A filename containing CR/LF cannot inject a response header.
  D3   Anti-vacuity for D1: a download returns the file's real bytes.
  C1   chmod refuses setuid, setgid, sticky, world-writable, and malformed modes.
  C2   Anti-vacuity for C1: an allowed mode is actually applied on disk.
  U1   An upload declaring a size over the cap is refused *before* its body is
       read, so an oversized upload never occupies memory or disk.
  U2   Anti-vacuity for U1: an upload larger than the panel's JSON body cap
       succeeds, proving the raw-body path exists rather than the route simply
       being small-capped.
  E1   The editor refuses to read a file above its cap rather than returning a
       truncated copy the operator could save back over the original.
  E2   A file the editor is willing to read can be written back unchanged. A
       read cap above the write cap is silent data loss, not a size limit.
  O1   A file created through the panel is chowned to the site's own UID.
  P1   A special file inside the jail cannot hang a panel worker thread.
  P2   A rejected upload leaves the connection usable.
  R1   Deleting a non-empty directory requires a typed confirmation and does
       nothing without one.
  R2   Anti-vacuity for R1: the correct confirmation deletes it.
  R3   The file-delete route declares itself destructive.

Contract pinned by these gates (the actor must match these names exactly):
  * `GET    /api/sites/<domain>/files?path=<rel>`
        200 `{"path": <normalised rel>, "entries": [{"name", "type", ...}]}`
        where `type` is one of `file`, `dir`, `symlink`.
  * `GET    /api/sites/<domain>/files/content?path=<rel>`
        200 `{"path": ..., "content": <text>}`
  * `PUT    /api/sites/<domain>/files/content`   body `{"path", "content"}`
  * `GET    /api/sites/<domain>/files/download?path=<rel>`
  * `POST   /api/sites/<domain>/files/upload?path=<rel>`   raw body = bytes
  * `POST   /api/sites/<domain>/files/mkdir`     body `{"path"}`
  * `POST   /api/sites/<domain>/files/rename`    body `{"path", "to"}`
  * `POST   /api/sites/<domain>/files/chmod`     body `{"path", "mode"}`
        `mode` is an octal *string* (`"0644"`). A JSON integer is not a mode:
        `644` decimal is `0o1204`, which is setuid.
  * `DELETE /api/sites/<domain>/files`           body `{"path", "confirm"}`
        `confirm` must equal the target's own name, matching the database-drop
        and site-delete confirmations already in the panel.
  * `wpfy.files.MAX_UPLOAD_BYTES` and `wpfy.files.MAX_EDIT_BYTES` are module
    constants, so these gates assert against the shipped values rather than
    hardcoding a number the actor is free to choose.

The jail root is the site's `app/` directory. Nothing above it is addressable.
"""

from __future__ import annotations

import hashlib
import http.client
import json
import os
import socket
import stat as stat_module
import threading
from pathlib import Path
from urllib.parse import urlencode

import pytest

GATE_TOKEN = "phase6-gate-token"
SEEDED_DOMAIN = "files.example"
OTHER_DOMAIN = "neighbour.example"
SECRET_MARKER = "PH6-DB-SECRET-4d7a1c"
ROOT_SECRET_MARKER = "PH6-ROOT-SECRET-9be402"
SFTP_SECRET_MARKER = "PH6-SFTP-SECRET-c05e13"
NEIGHBOUR_MARKER = "PH6-NEIGHBOUR-FILE-71ba9d"
ESCAPE_MARKER = "PH6-ESCAPED-WRITE-2f81aa"
SITE_UID = 1806

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

# Refused outright by every operation. Each entry is sent as the exact string
# below on both the query surface and the JSON-body surface, so no gate depends
# on how many times the panel happens to percent-decode.
TRAVERSAL_PATHS = (
    "..",
    "../",
    "../.env",
    "../compose.yaml",
    "../db-data",
    "../db-data/ibdata1",
    "./../.env",
    "sub/../../.env",
    "sub/../../../etc/passwd",
    "../../../../../../../../etc/passwd",
    f"../../{OTHER_DOMAIN}/.env",
    f"../../{OTHER_DOMAIN}/app/neighbour.txt",
    "/etc/passwd",
    "/",
    "//etc/passwd",
    "/var/www",
    "hello.txt\x00",
    "\x00../.env",
    "sub/\x00/nested.txt",
)

# Not required to be *refused* — an implementation may legitimately treat these
# as literal filenames inside the jail. They are required not to escape, which
# is what J3 checks. They exist because a handler that unquotes its own input a
# second time turns every one of them back into traversal.
ENCODED_PATHS = (
    "%2e%2e%2f.env",
    "..%2f.env",
    "%2e%2e/.env",
    "..%252f.env",
    "....//.env",
    "..;/.env",
)

UNSAFE_MODES = (
    "4755",   # setuid
    "04755",
    "2755",   # setgid
    "02755",
    "1777",   # sticky + world-writable
    "0777",
    "0666",
    "0646",   # world-writable
    "0602",
    "0757",
    "6755",
    "abc",
    "0o644",
    "-644",
    "",
    "07777",
    "999",
    "0644 ",
)

SAFE_MODES = ("0600", "0640", "0644", "0700", "0750", "0755")


def _files_path(domain: str, suffix: str = "", **query) -> str:
    base = f"/api/sites/{domain}/files{suffix}"
    return f"{base}?{urlencode(query)}" if query else base


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

    def header_names(self) -> set[str]:
        return {key.lower() for key, _ in self.headers}

    def json(self) -> dict:
        return json.loads(self.text)


class GateHome:
    def __init__(self, host: str, port: int, paths, root: Path):
        self.host = host
        self.port = port
        self.paths = paths
        self.root = root

    @property
    def site_dir(self) -> Path:
        return Path(self.paths.sites_dir) / SEEDED_DOMAIN

    @property
    def app(self) -> Path:
        return self.site_dir / "app"


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
        "DB_NAME=filesdb\n"
        "DB_USER=filesdb\n"
        f"DB_PASSWORD={SECRET_MARKER}\n"
        f"MARIADB_PASSWORD={SECRET_MARKER}\n"
        f"DB_ROOT_PASSWORD={ROOT_SECRET_MARKER}\n"
        f"MARIADB_ROOT_PASSWORD={ROOT_SECRET_MARKER}\n"
        f"SFTP_PASSWORD={SFTP_SECRET_MARKER}\n",
        encoding="utf-8",
    )
    (site / "compose.yaml").write_text("services: {}\n", encoding="utf-8")
    (site / "nginx" / "default.conf").write_text("server {\n    listen 8080;\n}\n", encoding="utf-8")
    (site / "nginx" / "extra" / "custom.conf").write_text("", encoding="utf-8")
    (site / "db-data" / "ibdata1").write_text(f"innodb {SECRET_MARKER}\n", encoding="utf-8")
    return site


def _seed_jail(app: Path) -> None:
    """Populate `app/` with the shapes the jail has to survive.

    The symlinks matter more than the regular files: they are exactly what a
    site's own SFTP user or a compromised plugin can create, without wpfy ever
    being consulted, between one panel request and the next.
    """
    (app / "sub").mkdir(parents=True, exist_ok=True)
    (app / "tree").mkdir(parents=True, exist_ok=True)
    (app / "index.php").write_text("<?php echo 'hello';\n", encoding="utf-8")
    (app / "hello.txt").write_text("hello-from-jail\n", encoding="utf-8")
    (app / "victim.txt").write_text("victim\n", encoding="utf-8")
    (app / "sub" / "nested.txt").write_text("nested\n", encoding="utf-8")
    (app / "tree" / "keep.txt").write_text("keep\n", encoding="utf-8")
    (app / "evil.html").write_text("<script>alert(document.cookie)</script>\n", encoding="utf-8")
    (app / "logo.svg").write_text("<svg xmlns='http://www.w3.org/2000/svg'><script/></svg>\n", encoding="utf-8")
    (app / "bundle.js").write_text("alert(1)\n", encoding="utf-8")

    os.symlink("../.env", app / "link_to_env")
    os.symlink("..", app / "link_to_site")
    os.symlink("/etc/passwd", app / "link_to_passwd")
    os.symlink("sub", app / "link_inside_dir")
    os.symlink("hello.txt", app / "link_inside_file")


@pytest.fixture
def gate_panel(tmp_path):
    """A real loopback panel over an isolated home with a populated site jail.

    Paths are redirected by mutating the frozen `settings.PATHS` singleton in
    place. `importlib.reload` is deliberately avoided: it reuses a module's
    __dict__, so symbols captured at import time by other test modules keep
    pointing at the old class while the module starts producing the new one,
    silently breaking unrelated tests with no possible teardown.

    `WPFY_SKIP_RUNTIME=1` is set because no file operation needs Docker; it
    makes nothing here vacuous. `WPFY_SKIP_CHOWN=1` is set so ordinary gates run
    as a normal user; the one gate that asserts ownership clears it itself.
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

    wpfy.registry._REGISTRY = None

    site = _seed_site(paths, SEEDED_DOMAIN, uid=SITE_UID)
    other = _seed_site(paths, OTHER_DOMAIN, uid=SITE_UID + 1)
    _seed_jail(site / "app")
    (other / "app" / "neighbour.txt").write_text(f"{NEIGHBOUR_MARKER}\n", encoding="utf-8")

    import wpfy.panel as panel

    config = panel.PanelConfig(host="127.0.0.1", port=0, token=GATE_TOKEN)
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
        for field, value in previous_paths.items():
            object.__setattr__(paths, field, value)
        wpfy.registry._REGISTRY = previous_registry
        for name, value in previous_env.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value


def _request(home, path, *, method="GET", body=None, raw=None, timeout=30) -> Response:
    connection = http.client.HTTPConnection(home.host, home.port, timeout=timeout)
    try:
        headers = {"Authorization": f"Bearer {GATE_TOKEN}"}
        payload = None
        if body is not None:
            payload = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        elif raw is not None:
            payload = raw
            headers["Content-Type"] = "application/octet-stream"
        connection.request(method, path, body=payload, headers=headers)
        response = connection.getresponse()
        return Response(response.status, response.read(), response.getheaders())
    finally:
        connection.close()


def _list(home, path, domain=SEEDED_DOMAIN) -> Response:
    return _request(home, _files_path(domain, "", path=path))


def _read(home, path, domain=SEEDED_DOMAIN) -> Response:
    return _request(home, _files_path(domain, "/content", path=path))


def _download(home, path, domain=SEEDED_DOMAIN) -> Response:
    return _request(home, _files_path(domain, "/download", path=path))


def _write(home, path, content, domain=SEEDED_DOMAIN) -> Response:
    return _request(home, _files_path(domain, "/content"), method="PUT",
                    body={"path": path, "content": content})


def _upload(home, path, data, domain=SEEDED_DOMAIN) -> Response:
    return _request(home, _files_path(domain, "/upload", path=path), method="POST", raw=data)


def _mkdir(home, path, domain=SEEDED_DOMAIN) -> Response:
    return _request(home, _files_path(domain, "/mkdir"), method="POST", body={"path": path})


def _rename(home, path, to, domain=SEEDED_DOMAIN) -> Response:
    return _request(home, _files_path(domain, "/rename"), method="POST", body={"path": path, "to": to})


def _chmod(home, path, mode, domain=SEEDED_DOMAIN) -> Response:
    return _request(home, _files_path(domain, "/chmod"), method="POST", body={"path": path, "mode": mode})


def _delete(home, path, confirm=None, domain=SEEDED_DOMAIN) -> Response:
    body = {"path": path}
    if confirm is not None:
        body["confirm"] = confirm
    return _request(home, _files_path(domain, ""), method="DELETE", body=body)


def _hostile_operations(home, path):
    """Every way a caller can name a path, including the ones easy to forget.

    `rename` is listed twice on purpose: the destination is a path the jail has
    to validate too, and an implementation that only checks the source moves a
    file anywhere on the host.
    """
    name = path.rstrip("/").rsplit("/", 1)[-1] or path
    return {
        "list": lambda: _list(home, path),
        "read": lambda: _read(home, path),
        "download": lambda: _download(home, path),
        "write": lambda: _write(home, path, ESCAPE_MARKER),
        "upload": lambda: _upload(home, path, ESCAPE_MARKER.encode("utf-8")),
        "mkdir": lambda: _mkdir(home, path),
        "rename_source": lambda: _rename(home, path, "moved.txt"),
        "rename_target": lambda: _rename(home, "victim.txt", path),
        "chmod": lambda: _chmod(home, path, "0600"),
        "delete": lambda: _delete(home, path, confirm=name),
    }


def _require_jail_is_served(home) -> None:
    """Precondition for every refusal gate below.

    404 is a legitimate answer for a path that does not exist, so — unlike
    earlier phases — a missing route cannot be told apart from a refusal by
    status alone. Proving the happy path works first is what stops every
    hostile-input gate in this file from passing against a panel that has no
    file routes at all.
    """
    response = _list(home, "sub")
    assert response.status == 200, (
        f"the file listing endpoint does not serve a legitimate path (status "
        f"{response.status}); without it every refusal gate in this file would "
        f"be vacuous: {response.text[:400]}"
    )
    document = response.json()
    assert "entries" in document, f"the listing response carries no `entries` key: {response.text[:400]}"


def _refused(response: Response, label: str) -> None:
    assert response.status < 500, (
        f"{label}: a hostile path caused a server error rather than a refusal "
        f"(status {response.status}): {response.text[:400]}"
    )
    assert not (200 <= response.status < 300), (
        f"{label}: a hostile path was accepted (status {response.status}): {response.text[:400]}"
    )


def _outside_jail_digest(paths) -> dict[str, str]:
    """Hash every file in both site trees except the jails themselves.

    This is the ground truth for "did anything escape": it does not care how the
    escape happened, only that the bytes above `app/` are exactly what they were.
    """
    digest: dict[str, str] = {}
    sites_root = Path(paths.sites_dir)
    for site in sorted(sites_root.iterdir()):
        if not site.is_dir():
            continue
        for current, dirnames, filenames in os.walk(site):
            current_path = Path(current)
            if current_path == site / "app":
                dirnames[:] = []
                continue
            for name in sorted(filenames):
                target = current_path / name
                try:
                    digest[str(target)] = hashlib.sha256(target.read_bytes()).hexdigest()
                except OSError as exc:
                    digest[str(target)] = f"unreadable:{exc.errno}"
    return digest


def _marker_hits_outside_jail(paths) -> list[str]:
    hits: list[str] = []
    sites_root = Path(paths.sites_dir)
    for site in sorted(sites_root.iterdir()):
        if not site.is_dir():
            continue
        for current, dirnames, filenames in os.walk(site):
            current_path = Path(current)
            if current_path == site / "app":
                dirnames[:] = []
                continue
            for name in sorted(filenames):
                target = current_path / name
                try:
                    if ESCAPE_MARKER in target.read_text(encoding="utf-8", errors="ignore"):
                        hits.append(str(target))
                except OSError:
                    continue
    return hits


# --------------------------------------------------------------------------
# J1 / J2 — the jail refuses traversal and still serves legitimate paths
# --------------------------------------------------------------------------

@pytest.mark.parametrize("operation", [
    "list", "read", "download", "write", "upload", "mkdir",
    "rename_source", "rename_target", "chmod", "delete",
])
def test_gate_every_operation_refuses_traversal(gate_panel, operation):
    """`../.env` is the first payload anyone tries, on every verb, not just read.

    Operations are parametrised rather than looped so a single unguarded verb is
    named directly in the failure rather than hidden behind whichever path
    happened to be checked first.
    """
    _require_jail_is_served(gate_panel)
    for path in TRAVERSAL_PATHS:
        response = _hostile_operations(gate_panel, path)[operation]()
        _refused(response, f"{operation} {path!r}")


def test_gate_legitimate_paths_reach_every_operation(gate_panel):
    """Anti-vacuity for the refusal gates: a jail that refuses everything is not secure, it is broken."""
    _require_jail_is_served(gate_panel)

    listing = _list(gate_panel, "")
    assert listing.status == 200, f"listing the jail root failed: {listing.text[:400]}"
    names = {entry["name"] for entry in listing.json()["entries"]}
    assert {"hello.txt", "sub", "tree"} <= names, f"the jail root listing is incomplete: {sorted(names)}"

    read = _read(gate_panel, "sub/nested.txt")
    assert read.status == 200, f"reading a nested file failed: {read.text[:400]}"
    assert "nested" in read.json()["content"], f"the read returned the wrong bytes: {read.text[:400]}"

    download = _download(gate_panel, "sub/nested.txt")
    assert download.status == 200, f"downloading a nested file failed: {download.text[:400]}"

    write = _write(gate_panel, "sub/written.txt", "written-by-gate\n")
    assert write.status in (200, 201), f"writing a nested file failed: {write.text[:400]}"
    assert (gate_panel.app / "sub" / "written.txt").read_text(encoding="utf-8") == "written-by-gate\n"

    upload = _upload(gate_panel, "sub/uploaded.bin", b"uploaded-by-gate")
    assert upload.status in (200, 201), f"uploading a nested file failed: {upload.text[:400]}"
    assert (gate_panel.app / "sub" / "uploaded.bin").read_bytes() == b"uploaded-by-gate"

    mkdir = _mkdir(gate_panel, "sub/made")
    assert mkdir.status in (200, 201), f"creating a nested directory failed: {mkdir.text[:400]}"
    assert (gate_panel.app / "sub" / "made").is_dir()

    rename = _rename(gate_panel, "victim.txt", "sub/renamed.txt")
    assert rename.status == 200, f"renaming into a subdirectory failed: {rename.text[:400]}"
    assert (gate_panel.app / "sub" / "renamed.txt").exists()

    chmod = _chmod(gate_panel, "hello.txt", "0640")
    assert chmod.status == 200, f"chmod with an allowed mode failed: {chmod.text[:400]}"

    delete = _delete(gate_panel, "sub/renamed.txt", confirm="renamed.txt")
    assert delete.status == 200, f"deleting a nested file failed: {delete.text[:400]}"
    assert not (gate_panel.app / "sub" / "renamed.txt").exists()


# --------------------------------------------------------------------------
# J3 — nothing above the jail changes, whatever the path spelling
# --------------------------------------------------------------------------

def test_gate_no_hostile_path_touches_anything_outside_the_jail(gate_panel):
    """The escape check that does not care *how* the escape was spelled.

    Encoded forms are included here but not in the refusal gate on purpose: an
    implementation may legitimately treat `%2e%2e%2f.env` as a literal filename
    inside the jail. What it may never do is decode it a second time and act on
    the result.
    """
    _require_jail_is_served(gate_panel)
    before = _outside_jail_digest(gate_panel.paths)
    assert before, "the digest is empty, so this gate would pass against any implementation"

    for path in TRAVERSAL_PATHS + ENCODED_PATHS:
        for label, call in _hostile_operations(gate_panel, path).items():
            response = call()
            assert response.status < 500, (
                f"{label} {path!r} caused a server error: {response.text[:300]}"
            )
            for secret in (SECRET_MARKER, ROOT_SECRET_MARKER, SFTP_SECRET_MARKER, NEIGHBOUR_MARKER):
                assert secret not in response.text, (
                    f"{label} {path!r} returned content from outside the jail: {response.text[:300]}"
                )

    after = _outside_jail_digest(gate_panel.paths)
    assert after == before, (
        "files outside the jail changed while hostile paths were exercised: "
        f"{sorted(set(before) ^ set(after)) or [k for k in before if before[k] != after.get(k)]}"
    )
    assert not _marker_hits_outside_jail(gate_panel.paths), (
        f"a write escaped the jail: {_marker_hits_outside_jail(gate_panel.paths)}"
    )


# --------------------------------------------------------------------------
# J4 / J5 / J6 — symlinks
# --------------------------------------------------------------------------

def test_gate_symlinks_escaping_the_jail_are_never_followed(gate_panel):
    """The site's own users can create these; wpfy is never consulted first."""
    _require_jail_is_served(gate_panel)
    escaping = (
        "link_to_env",
        "link_to_passwd",
        "link_to_site",
        "link_to_site/.env",
        "link_to_site/compose.yaml",
        "link_to_site/db-data/ibdata1",
    )
    for path in escaping:
        for label, call in _hostile_operations(gate_panel, path).items():
            response = call()
            _refused(response, f"{label} via symlink {path!r}")
            for secret in (SECRET_MARKER, ROOT_SECRET_MARKER, SFTP_SECRET_MARKER):
                assert secret not in response.text, (
                    f"{label} via symlink {path!r} leaked a site secret: {response.text[:300]}"
                )
    assert (gate_panel.site_dir / ".env").exists(), "the site's .env was removed through a symlink"
    assert not _marker_hits_outside_jail(gate_panel.paths), "a write escaped through a symlink"


def test_gate_symlink_components_inside_the_jail_are_not_traversed(gate_panel):
    """The gate that separates an lstat walk from a realpath containment check.

    `link_inside_dir` points at `sub`, and `link_inside_file` at `hello.txt`.
    Both resolve to targets inside the jail, so a containment check accepts
    them and every other symlink gate in this file still passes. Only a walk
    that lstats each component and refuses `S_ISLNK` outright rejects these —
    which is the point, because containment is decided before the open and the
    link can be repointed after it.
    """
    _require_jail_is_served(gate_panel)
    for path in ("link_inside_dir", "link_inside_dir/nested.txt", "link_inside_file"):
        _refused(_read(gate_panel, path), f"read through contained symlink {path!r}")
        _refused(_download(gate_panel, path), f"download through contained symlink {path!r}")
        _refused(_write(gate_panel, path, ESCAPE_MARKER), f"write through contained symlink {path!r}")
        _refused(_upload(gate_panel, path, b"x"), f"upload through contained symlink {path!r}")
        _refused(_chmod(gate_panel, path, "0600"), f"chmod through contained symlink {path!r}")
    assert (gate_panel.app / "hello.txt").read_text(encoding="utf-8") == "hello-from-jail\n", (
        "a write reached the symlink's target instead of being refused"
    )
    assert (gate_panel.app / "sub" / "nested.txt").read_text(encoding="utf-8") == "nested\n"


def test_gate_listing_reports_symlinks_without_following_them(gate_panel):
    """Refusing to *traverse* a symlink must not mean refusing to *show* it.

    A jail that errors on any directory containing a symlink is unusable: a
    single link anywhere in wp-content hides the whole tree from the operator.
    """
    _require_jail_is_served(gate_panel)
    response = _list(gate_panel, "")
    assert response.status == 200, (
        f"listing a directory that contains symlinks failed: {response.text[:400]}"
    )
    entries = {entry["name"]: entry for entry in response.json()["entries"]}
    for name in ("link_to_env", "link_to_site", "link_inside_dir", "link_inside_file"):
        assert name in entries, f"the listing hid a symlink instead of reporting it: {sorted(entries)}"
        assert entries[name]["type"] == "symlink", (
            f"{name} was reported as {entries[name]['type']!r}; a followed symlink is "
            f"indistinguishable from a real file in the UI"
        )
    assert entries["hello.txt"]["type"] == "file"
    assert entries["sub"]["type"] == "dir"


# --------------------------------------------------------------------------
# J7 / J8 — secrets and cross-site isolation
# --------------------------------------------------------------------------

def test_gate_site_secrets_are_unreachable_through_the_file_manager(gate_panel):
    """`.env` holds DB_PASSWORD, DB_ROOT_PASSWORD and the SFTP password.

    It sits one directory above the jail root, which is the entire reason the
    jail root is `app/` and not the site directory.
    """
    _require_jail_is_served(gate_panel)
    for path in ("../.env", ".env", "/.env", "../../.env", "link_to_env", "link_to_site/.env"):
        for call in (_read, _download, _list):
            response = call(gate_panel, path)
            assert response.status < 500, f"{path!r} caused a server error: {response.text[:300]}"
            for secret in (SECRET_MARKER, ROOT_SECRET_MARKER, SFTP_SECRET_MARKER):
                assert secret not in response.text, (
                    f"a site secret was served through the file manager via {path!r}: "
                    f"{response.text[:300]}"
                )


def test_gate_one_sites_file_routes_never_reach_another_site(gate_panel):
    """Per-site isolation is a hard rule of this project, not a panel convenience."""
    _require_jail_is_served(gate_panel)
    reachable = _list(gate_panel, "", domain=OTHER_DOMAIN)
    assert reachable.status == 200, (
        f"the neighbour site is not addressable at all, so this gate would be "
        f"vacuous: {reachable.text[:300]}"
    )
    assert NEIGHBOUR_MARKER in reachable.text or "neighbour.txt" in reachable.text, (
        f"the neighbour's own jail does not contain its seeded file: {reachable.text[:300]}"
    )

    for path in (f"../../{OTHER_DOMAIN}/app/neighbour.txt", f"../../{OTHER_DOMAIN}/.env",
                 f"/{OTHER_DOMAIN}/app/neighbour.txt"):
        for call in (_read, _download, _list):
            response = call(gate_panel, path)
            assert NEIGHBOUR_MARKER not in response.text, (
                f"{SEEDED_DOMAIN} read {OTHER_DOMAIN}'s files via {path!r}: {response.text[:300]}"
            )
        _refused(_write(gate_panel, path, ESCAPE_MARKER), f"cross-site write {path!r}")
    assert (Path(gate_panel.paths.sites_dir) / OTHER_DOMAIN / "app" / "neighbour.txt").read_text(
        encoding="utf-8") == f"{NEIGHBOUR_MARKER}\n", "the neighbour's file was overwritten"


# --------------------------------------------------------------------------
# D1 / D2 / D3 — downloads cannot execute in the panel's origin
# --------------------------------------------------------------------------

@pytest.mark.parametrize("name", ["evil.html", "logo.svg", "bundle.js", "index.php", "hello.txt"])
def test_gate_downloads_are_always_forced_attachments(gate_panel, name):
    """`app/` is full of attacker-influenced files and the panel holds the bearer token.

    An uploaded `.html` served as `text/html` from the panel's own origin is
    stored XSS against the panel, and the CSP on `index.html` does not cover a
    document the browser navigated to directly.
    """
    _require_jail_is_served(gate_panel)
    response = _download(gate_panel, name)
    assert response.status == 200, f"downloading {name} failed: {response.text[:300]}"
    content_type = (response.header("Content-Type") or "").lower()
    assert content_type.startswith("application/octet-stream"), (
        f"{name} was served as {content_type!r}; site content must never carry a "
        f"renderable content type in the panel's origin"
    )
    disposition = (response.header("Content-Disposition") or "").lower()
    assert disposition.startswith("attachment"), (
        f"{name} was served with Content-Disposition {disposition!r}"
    )
    assert (response.header("X-Content-Type-Options") or "").lower() == "nosniff", (
        f"{name} was served without nosniff, so the browser may sniff it back to HTML"
    )


def test_gate_download_filenames_cannot_inject_response_headers(gate_panel):
    """POSIX allows CR and LF in filenames; `send_header` does not sanitise them."""
    _require_jail_is_served(gate_panel)
    hostile = 'inject\r\nX-Wpfy-Injected: yes\r\nX-Other: "quoted".txt'
    (gate_panel.app / hostile).write_text("payload\n", encoding="utf-8")
    try:
        response = _download(gate_panel, hostile)
    except http.client.HTTPException as exc:
        pytest.fail(f"a CR/LF filename corrupted the response stream: {exc}")
    assert "x-wpfy-injected" not in response.header_names(), (
        f"a filename injected a response header: {response.headers}"
    )
    if 200 <= response.status < 300:
        disposition = response.header("Content-Disposition") or ""
        assert "\n" not in disposition and "\r" not in disposition, (
            f"raw CR/LF reached the Content-Disposition header: {disposition!r}"
        )


def test_gate_download_returns_the_real_bytes(gate_panel):
    """Anti-vacuity for the header gates: forced headers on an empty body prove nothing."""
    _require_jail_is_served(gate_panel)
    payload = bytes(range(256)) * 8
    (gate_panel.app / "binary.dat").write_bytes(payload)
    response = _download(gate_panel, "binary.dat")
    assert response.status == 200, f"downloading a binary file failed: {response.text[:300]}"
    assert response.body == payload, (
        f"the download returned {len(response.body)} bytes, expected {len(payload)}"
    )


# --------------------------------------------------------------------------
# C1 / C2 — the chmod whitelist
# --------------------------------------------------------------------------

def test_gate_chmod_refuses_unsafe_modes(gate_panel):
    """setuid/setgid/world-writable in a web root is a privilege escalation primitive.

    A JSON *integer* is refused too: `644` decimal is `0o1204`, which sets the
    setuid bit. An implementation that accepts ints and passes them to
    `os.chmod` grants exactly what this gate exists to prevent.
    """
    _require_jail_is_served(gate_panel)
    target = gate_panel.app / "hello.txt"
    target.chmod(0o644)
    for mode in UNSAFE_MODES:
        response = _chmod(gate_panel, "hello.txt", mode)
        _refused(response, f"chmod {mode!r}")
        assert stat_module.S_IMODE(target.stat().st_mode) == 0o644, (
            f"chmod {mode!r} was refused but changed the mode anyway"
        )
    integer = _chmod(gate_panel, "hello.txt", 644)
    _refused(integer, "chmod with a JSON integer mode")
    assert stat_module.S_IMODE(target.stat().st_mode) == 0o644


@pytest.mark.parametrize("mode", SAFE_MODES)
def test_gate_chmod_applies_an_allowed_mode(gate_panel, mode):
    """Anti-vacuity for the whitelist: refusing every mode is not a whitelist."""
    _require_jail_is_served(gate_panel)
    response = _chmod(gate_panel, "hello.txt", mode)
    assert response.status == 200, f"chmod {mode!r} was refused: {response.text[:300]}"
    actual = stat_module.S_IMODE((gate_panel.app / "hello.txt").stat().st_mode)
    assert actual == int(mode, 8), f"chmod {mode!r} left the mode at {oct(actual)}"


# --------------------------------------------------------------------------
# U1 / U2 — uploads
# --------------------------------------------------------------------------

def test_gate_oversized_upload_is_refused_before_its_body_is_read(gate_panel):
    """A cap enforced after reading the body is not a cap; it is the attack.

    The request below declares a size over the limit and then sends almost
    nothing. A handler that reads `Content-Length` bytes before checking blocks
    forever and this gate times out — which is the observable difference between
    streaming with a cap and buffering the whole upload first.
    """
    _require_jail_is_served(gate_panel)
    import wpfy.files as files

    cap = files.MAX_UPLOAD_BYTES
    assert isinstance(cap, int) and cap > 0, f"MAX_UPLOAD_BYTES is not a positive int: {cap!r}"

    connection = http.client.HTTPConnection(gate_panel.host, gate_panel.port, timeout=15)
    try:
        connection.putrequest("POST", _files_path(SEEDED_DOMAIN, "/upload", path="huge.bin"))
        connection.putheader("Authorization", f"Bearer {GATE_TOKEN}")
        connection.putheader("Content-Type", "application/octet-stream")
        connection.putheader("Content-Length", str(cap + 1))
        connection.endheaders()
        try:
            connection.send(b"x" * 4096)
        except (BrokenPipeError, ConnectionResetError):
            pass
        try:
            response = connection.getresponse()
        except socket.timeout:
            pytest.fail(
                "the upload route read the declared body length before checking it "
                "against MAX_UPLOAD_BYTES, so an oversized upload is buffered rather "
                "than refused"
            )
        assert response.status in (400, 413), (
            f"an upload declaring {cap + 1} bytes was answered {response.status}"
        )
    finally:
        connection.close()
    assert not (gate_panel.app / "huge.bin").exists(), "a refused upload still created its file"


def test_gate_upload_is_not_capped_by_the_json_body_limit(gate_panel):
    """Anti-vacuity for the cap gate, and proof the raw-body path exists.

    The panel's JSON reader refuses anything over 64 KiB. A file manager whose
    uploads go through it cannot receive a plugin zip, and would pass the
    oversize gate above for entirely the wrong reason.
    """
    _require_jail_is_served(gate_panel)
    import wpfy.files as files
    import wpfy.panel as panel

    assert files.MAX_UPLOAD_BYTES > panel._MAX_BODY_BYTES, (
        f"MAX_UPLOAD_BYTES ({files.MAX_UPLOAD_BYTES}) is not above the panel's JSON "
        f"body cap ({panel._MAX_BODY_BYTES}); uploads are still limited to a JSON body"
    )
    payload = os.urandom(min(files.MAX_UPLOAD_BYTES - 1, panel._MAX_BODY_BYTES * 4))
    response = _upload(gate_panel, "plugin.zip", payload)
    assert response.status in (200, 201), (
        f"a {len(payload)}-byte upload was refused: {response.status} {response.text[:300]}"
    )
    assert (gate_panel.app / "plugin.zip").read_bytes() == payload, "the upload was corrupted on the way to disk"


# --------------------------------------------------------------------------
# E1 / E2 — the editor cannot silently truncate
# --------------------------------------------------------------------------

def test_gate_editor_refuses_oversized_files_instead_of_truncating(gate_panel):
    """Truncated-on-read plus saved-back is silent data loss, not a size limit."""
    _require_jail_is_served(gate_panel)
    import wpfy.files as files

    cap = files.MAX_EDIT_BYTES
    assert isinstance(cap, int) and cap > 0, f"MAX_EDIT_BYTES is not a positive int: {cap!r}"
    big = gate_panel.app / "big.txt"
    big.write_text("A" * (cap + 1024), encoding="utf-8")

    response = _read(gate_panel, "big.txt")
    _refused(response, "editor read of an oversized file")
    if 200 <= response.status < 300:  # pragma: no cover - _refused already failed
        pytest.fail("unreachable")

    download = _download(gate_panel, "big.txt")
    assert download.status == 200, (
        f"a file too large to edit must still be downloadable: {download.text[:300]}"
    )
    assert len(download.body) == cap + 1024, "the download truncated the file"


def test_gate_a_file_the_editor_can_read_can_be_written_back(gate_panel):
    """A read cap above the write cap loses the operator's edit at save time.

    Reading is capped by MAX_EDIT_BYTES; writing goes through the panel's JSON
    body reader. If the second is smaller, the editor opens a file it can never
    save, and the operator finds out only after typing.
    """
    _require_jail_is_served(gate_panel)
    import wpfy.files as files

    content = "B" * (files.MAX_EDIT_BYTES - 1024)
    (gate_panel.app / "editable.txt").write_text(content, encoding="utf-8")

    read = _read(gate_panel, "editable.txt")
    assert read.status == 200, f"reading a file just under the edit cap failed: {read.text[:300]}"
    assert read.json()["content"] == content, "the editor read back different content"

    write = _write(gate_panel, "editable.txt", content)
    assert write.status in (200, 201), (
        f"a file the editor was willing to read could not be written back "
        f"(status {write.status}): {write.text[:300]}"
    )
    assert (gate_panel.app / "editable.txt").read_text(encoding="utf-8") == content


# --------------------------------------------------------------------------
# O1 — ownership
# --------------------------------------------------------------------------

def test_gate_created_files_are_owned_by_the_site_uid(gate_panel, monkeypatch):
    """wpfy runs as root; a root-owned file in the web root breaks the site's own updater.

    This is asserted at the syscall rather than by stat because the suite does
    not run as root. `geteuid` is faked so the ownership path is taken, and both
    `chown` and `fchown` are accepted so the gate does not dictate which one the
    implementation uses.
    """
    _require_jail_is_served(gate_panel)
    monkeypatch.delenv("WPFY_SKIP_CHOWN", raising=False)
    monkeypatch.setattr(os, "geteuid", lambda: 0)

    recorded: list[tuple[int, int]] = []
    monkeypatch.setattr(os, "chown", lambda path, uid, gid, **kwargs: recorded.append((uid, gid)))
    monkeypatch.setattr(os, "fchown", lambda fd, uid, gid: recorded.append((uid, gid)))

    upload = _upload(gate_panel, "owned.bin", b"owned-by-gate")
    assert upload.status in (200, 201), f"the upload failed: {upload.text[:300]}"
    assert recorded, "an uploaded file was never chowned, so it stays root-owned in the web root"
    assert (SITE_UID, SITE_UID) in recorded, (
        f"the upload was chowned to {recorded} rather than the site's own uid {SITE_UID}"
    )

    recorded.clear()
    write = _write(gate_panel, "owned.txt", "owned-by-gate\n")
    assert write.status in (200, 201), f"the write failed: {write.text[:300]}"
    assert (SITE_UID, SITE_UID) in recorded, (
        f"an edited file was chowned to {recorded} rather than the site's own uid {SITE_UID}"
    )


# --------------------------------------------------------------------------
# P1 / P2 — the jail's failure modes must not take the panel with them
# --------------------------------------------------------------------------

def test_gate_special_files_cannot_hang_a_panel_worker(gate_panel):
    """`open(O_RDONLY)` on a FIFO blocks until a writer appears. There is no writer.

    A regular-file check performed *after* the open is too late: the thread is
    already gone. `app/` is writable by the site's own SFTP user and by its PHP,
    so a compromised WordPress install can plant one and hang a panel worker per
    request — the panel serves one thread per connection.

    The fix is a flag, not a redesign: `O_NONBLOCK` makes the open return
    immediately on a FIFO, and the existing `S_ISREG` check then rejects it.
    """
    _require_jail_is_served(gate_panel)
    os.mkfifo(gate_panel.app / "pipe")
    for label, call in (("read", _read), ("download", _download)):
        try:
            response = call(gate_panel, "pipe")
        except (socket.timeout, TimeoutError, http.client.HTTPException) as exc:
            pytest.fail(
                f"{label} of a FIFO hung a panel worker thread ({type(exc).__name__}); "
                f"the open blocked waiting for a writer that never comes"
            )
        _refused(response, f"{label} of a FIFO")
    try:
        chmod = _chmod(gate_panel, "pipe", "0600")
    except (socket.timeout, TimeoutError, http.client.HTTPException) as exc:
        pytest.fail(f"chmod of a FIFO hung a panel worker thread ({type(exc).__name__})")
    assert chmod.status < 500, f"chmod of a FIFO caused a server error: {chmod.text[:300]}"


def test_gate_a_rejected_upload_leaves_the_connection_usable(gate_panel):
    """Refusing an upload before reading its body strands that body in the socket.

    The next request on the same keep-alive connection is then parsed from the
    middle of the discarded payload. Browsers reuse connections, so one rejected
    upload silently corrupts whatever the operator does next.

    Either fix passes: close the connection after refusing, or drain the body.
    This gate pins the property, not the mechanism.
    """
    _require_jail_is_served(gate_panel)
    connection = http.client.HTTPConnection(gate_panel.host, gate_panel.port, timeout=15)
    try:
        connection.request(
            "POST", _files_path(SEEDED_DOMAIN, "/upload", path="../escape.txt"),
            body=b"x" * (256 * 1024),
            headers={"Authorization": f"Bearer {GATE_TOKEN}", "Content-Type": "application/octet-stream"},
        )
        first = connection.getresponse()
        first.read()
        assert first.status >= 400, f"a traversal upload was accepted: {first.status}"

        try:
            connection.request(
                "GET", _files_path(SEEDED_DOMAIN, "", path=""),
                headers={"Authorization": f"Bearer {GATE_TOKEN}"},
            )
            second = connection.getresponse()
            body = second.read()
        except (OSError, http.client.HTTPException) as exc:
            pytest.fail(
                f"the connection was unusable after a rejected upload "
                f"({type(exc).__name__}: {exc}); the refused body was left in the socket"
            )
        assert second.status == 200, (
            f"the request after a rejected upload was answered {second.status}, so the "
            f"stranded body was parsed as the next request: {body[:200]!r}"
        )
        assert b"hello.txt" in body, f"the response after a rejected upload is not a listing: {body[:200]!r}"
    finally:
        connection.close()


# --------------------------------------------------------------------------
# R1 / R2 / R3 — destructive deletes
# --------------------------------------------------------------------------

def test_gate_non_empty_directory_delete_requires_typed_confirmation(gate_panel):
    """A recursive delete in the web root is unrecoverable without a backup."""
    _require_jail_is_served(gate_panel)
    for confirm in (None, "", "yes", "tree/", "wrong", f"{SEEDED_DOMAIN}"):
        response = _delete(gate_panel, "tree", confirm=confirm)
        _refused(response, f"directory delete with confirm={confirm!r}")
        assert (gate_panel.app / "tree" / "keep.txt").exists(), (
            f"the directory was deleted despite confirm={confirm!r} being refused"
        )


def test_gate_confirmed_directory_delete_removes_it(gate_panel):
    """Anti-vacuity for the confirmation gate."""
    _require_jail_is_served(gate_panel)
    response = _delete(gate_panel, "tree", confirm="tree")
    assert response.status == 200, f"a correctly confirmed delete failed: {response.text[:300]}"
    assert not (gate_panel.app / "tree").exists(), "the confirmed delete left the directory in place"


def test_gate_file_delete_route_declares_itself_destructive(gate_panel):
    """The route table is what tells later phases which verbs need a confirmation."""
    import wpfy.panel as panel

    matches = [route for route in panel._ROUTES
               if route.method == "DELETE" and "files" in route.pattern.pattern]
    assert matches, "no DELETE route exists for the file manager"
    for route in matches:
        assert route.meta.destructive, (
            f"{route.pattern.pattern} deletes operator data but is not declared destructive"
        )
