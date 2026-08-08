"""Tests for the WPFY panel-auth Fail2ban filter + jail (t12, Phase 4/12).

The filter parses the t09 fixed 6-key JSONL schema from panel-auth.log and
must match ONLY valid WPFY panel failure records (extracting the resolved
trusted client IP), rejecting everything else: success lines, malformed JSON,
embedded newlines, injection attempts, the 0.0.0.0 never-ban sentinel
(proxy/loopback/Cloudflare/edge identities are redacted to it upstream),
missing fields, and unrelated WPFY events.

fail2ban-regex is not installed on macOS; the fixture matrix is run in Python
mimicking fail2ban 1.0 regex semantics (single-line compile, per-line
``match`` + ``search``, ban target extracted from the failure-id group
``ip4``/``ip6``). The shared harness enforces the 1.0 failure-id contract that
a legacy ``(?P<host>...)`` group violates (t20 blocker).
A live ``fail2ban-regex`` run is scheduled at t21; when the binary is present
the CLI test executes it directly against the fixture files.
"""

from __future__ import annotations

import hashlib
import importlib
import ipaddress
import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

import wpfy.fail2ban_host as f2b_host
from tests.fail2ban_harness import FAIL2BAN_FLAGS, compile_failregex, extract_fid

@pytest.fixture
def auth_log_home(tmp_path, monkeypatch):
    """Redirect WPFY paths and reset panel_auth state (mirrors test_panel_auth_log)."""
    import wpfy.panel_auth as panel_auth
    import wpfy.settings as settings

    paths = settings.PATHS
    previous = {
        "install_root": paths.install_root,
        "config_dir": paths.config_dir,
        "state_dir": paths.state_dir,
        "log_dir": paths.log_dir,
    }
    for field in previous:
        object.__setattr__(paths, field, str(tmp_path / field))
    Path(paths.config_dir).mkdir(parents=True)
    Path(paths.state_dir).mkdir(parents=True)
    Path(paths.log_dir).mkdir(parents=True)
    panel_auth.reset_state()
    try:
        yield paths
    finally:
        panel_auth.reset_state()
        for field, value in previous.items():
            object.__setattr__(paths, field, value)


# ---------------------------------------------------------------------------
# fail2ban regex-semantics harness
# ---------------------------------------------------------------------------

# fail2ban 1.0 compiles each failregex standalone against a single physical
# line: no MULTILINE, no DOTALL (harness encodes the failure-id contract too).
_F2B_FLAGS = FAIL2BAN_FLAGS

_PANEL_FILTER_CACHE: dict[str, re.Pattern | None] = {}


def _panel_failregex() -> str:
    content = f2b_host.panel_filter_content()
    for line in content.splitlines():
        if line.startswith("failregex"):
            return line.split("=", 1)[1].strip()
    raise AssertionError("panel filter content has no failregex")


def _compile_panel_filter() -> re.Pattern:
    if "rx" not in _PANEL_FILTER_CACHE:
        _PANEL_FILTER_CACHE["rx"] = compile_failregex(_panel_failregex())
    return _PANEL_FILTER_CACHE["rx"]


def _f2b_match(line: str) -> re.Match | None:
    """Mimic fail2ban line handling: strip newline, then match (anchored)."""
    rx = _compile_panel_filter()
    return rx.match(line.rstrip("\n"))


def _f2b_search(line: str) -> re.Match | None:
    """Mimic a hypothetical search-based fail2ban matcher for robustness."""
    rx = _compile_panel_filter()
    return rx.search(line.rstrip("\n"))


def _assert_matches(line: str, host: str | None) -> None:
    match = _f2b_match(line)
    if host is None:
        assert match is None, f"expected NO match, got host={match and extract_fid(match)!r}: {line}"
    else:
        assert match is not None, f"expected match for host {host!r}: {line}"
        assert extract_fid(match) == host, f"wrong host extracted: {line}"
    # search and match must agree for the anchored strict pattern.
    assert (_f2b_search(line) is not None) == (host is not None), (
        f"match/search disagree: {line}"
    )


# ---------------------------------------------------------------------------
# Fixture line builders (writer emits json.dumps(..., ensure_ascii=True,
# separators=(",", ":")) in fixed key order)
# ---------------------------------------------------------------------------


def _record(
    client_ip: str = "203.0.113.8",
    surface: str = "password",
    reason: str = "invalid_credentials",
    event: str = "panel_auth_failure",
    timestamp: str = "2026-08-06T06:20:14Z",
    account_hash: str | None = None,
    *,
    order: list[str] | None = None,
    extra: dict | None = None,
) -> str:
    record = {
        "timestamp": timestamp,
        "event": event,
        "surface": surface,
        "client_ip": client_ip,
        "account_hash": account_hash or ("sha256:" + "a" * 64),
        "reason_class": reason,
    }
    if extra:
        record.update(extra)
    if order:
        record = {key: record[key] for key in order}
    return json.dumps(record, ensure_ascii=True, separators=(",", ":"))


_V4 = "203.0.113.8"
_V6 = "2001:db8::1"


# ---------------------------------------------------------------------------
# Filter regex: valid records MUST match and extract the client IP
# ---------------------------------------------------------------------------


def test_valid_ipv4_failure_matches():
    _assert_matches(_record(client_ip=_V4), _V4)


def test_valid_ipv6_failure_matches():
    _assert_matches(_record(client_ip=_V6), _V6)


def test_valid_ipv6_loopback_extracts():
    # ::1 never reaches the log (emission guard redacts it), but a present
    # record is a valid IPv6 identity; the filter must handle it and the jail
    # allowlist makes banning it a no-op.
    _assert_matches(_record(client_ip="::1"), "::1")


def test_all_surfaces_match():
    for surface in ("password", "setup", "setup_totp"):
        _assert_matches(_record(surface=surface), _V4)


def test_all_reason_classes_match():
    for reason in ("invalid_credentials", "totp_failed", "locked", "throttled"):
        _assert_matches(_record(reason=reason), _V4)


def test_real_writer_injection_username_still_matches(auth_log_home):
    # An injection-like username is JSON-escaped and hashed upstream; the
    # resulting record is a genuine failure and must match, extracting the
    # real resolved client IP (never the raw username).
    import wpfy.panel_auth as panel_auth

    panel_auth.add_user("admin", "admin-password", role=panel_auth.ROLE_ADMIN)
    evil = 'evil"}\n{"event":"x'
    assert panel_auth.login(evil, "wrong", client="203.0.113.77") is None

    log_path = Path(auth_log_home.log_dir) / "panel-auth.log"
    raw = log_path.read_text(encoding="utf-8")
    lines = [line for line in raw.splitlines() if line.strip()]
    assert len(lines) == 1
    assert evil not in raw
    _assert_matches(lines[0], "203.0.113.77")


# ---------------------------------------------------------------------------
# Filter regex: invalid records MUST NOT match
# ---------------------------------------------------------------------------


def test_success_or_other_event_rejected():
    _assert_matches(_record(event="panel_auth_success"), None)
    _assert_matches(_record(event="site.security.fail2ban.on"), None)
    _assert_matches(_record(event="login_shield.health_failed"), None)


def test_malformed_json_rejected():
    _assert_matches('{"timestamp":"2026-08-06T06:20:14Z","event":"panel_auth_failure"', None)
    _assert_matches("not json at all", None)
    _assert_matches("", None)


def test_missing_fields_rejected():
    # Only event + client_ip present.
    _assert_matches('{"event":"panel_auth_failure","client_ip":"203.0.113.8"}', None)
    # Missing trailing reason_class (valid JSON, wrong shape).
    _assert_matches(
        '{"timestamp":"2026-08-06T06:20:14Z","event":"panel_auth_failure",'
        '"surface":"password","client_ip":"203.0.113.8","account_hash":"sha256:' + "a" * 64 + '"}',
        None,
    )
    # Missing account_hash.
    _assert_matches(
        '{"timestamp":"2026-08-06T06:20:14Z","event":"panel_auth_failure",'
        '"surface":"password","client_ip":"203.0.113.8","reason_class":"invalid_credentials"}',
        None,
    )


def test_wrong_key_order_rejected():
    # The writer emits a fixed key order; any other order is not a WPFY record.
    _assert_matches(
        _record(order=["event", "timestamp", "surface", "client_ip", "account_hash", "reason_class"]),
        None,
    )


def test_extra_key_rejected():
    _assert_matches(_record(extra={"extra": 1}), None)


def test_never_ban_sentinel_rejected():
    # Proxy / loopback / Docker bridge / Cloudflare edge / trusted edge are
    # redacted to 0.0.0.0 at emission; banning the sentinel is a no-op, so the
    # filter must never extract it.
    _assert_matches(_record(client_ip="0.0.0.0"), None)


def test_non_ip_client_rejected():
    _assert_matches(_record(client_ip="not-an-ip"), None)
    _assert_matches(_record(client_ip="203.0.113"), None)
    _assert_matches(_record(client_ip=""), None)


def test_wrong_event_with_valid_shape_rejected():
    _assert_matches(
        _record(event="panel_auth_failure", extra={"event": "panel_auth_success"}), None
    )


def test_wrong_account_hash_rejected():
    # Not sha256:64hex.
    _assert_matches(_record(account_hash="plaintext-username"), None)
    _assert_matches(_record(account_hash="sha256:" + "a" * 63), None)
    _assert_matches(_record(account_hash="sha256:" + "a" * 64 + "g"), None)


def test_injection_in_hash_rejected():
    # A quote or newline escape inside the hashed value breaks the strict
    # schema and must not match (attacker-controlled bytes never enter fields).
    _assert_matches(_record(account_hash='sha256:"' + "a" * 63), None)
    _assert_matches(_record(account_hash="sha256:" + "a" * 64 + "\\n"), None)


def test_embedded_newline_rejected():
    # An actual newline split across two physical lines: neither line matches.
    _assert_matches(
        '{"timestamp":"2026-08-06T06:20:14Z","event":"panel_auth_failure",',
        None,
    )
    _assert_matches(
        '"surface":"password","client_ip":"203.0.113.8","account_hash":"sha256:' + "a" * 64 + '","reason_class":"invalid_credentials"}',
        None,
    )
    # A literal backslash-n sequence inside a constrained field.
    _assert_matches(
        '{"timestamp":"2026-08-06T06:20:14Z","event":"panel_auth_failure",'
        '"surface":"password","client_ip":"203.0.113.8","account_hash":"sha256:' + "a" * 64 + r'\n","reason_class":"invalid_credentials"}',
        None,
    )


def test_unknown_surface_and_reason_rejected():
    _assert_matches(_record(surface="recovery"), None)
    _assert_matches(_record(reason="brute_force"), None)


def test_wrong_timestamp_format_rejected():
    _assert_matches(_record(timestamp="2026-08-06 06:20:14"), None)
    _assert_matches(_record(timestamp="2026-08-06T06:20:14"), None)


def test_trailing_garbage_rejected():
    _assert_matches(_record() + " garbage", None)


def test_raw_forwarded_header_never_parsed():
    # fail2ban must never parse raw client-supplied forwarded headers; the log
    # carries only the WPFY-resolved trusted client IP (t02).
    _assert_matches("X-Forwarded-For: 203.0.113.8", None)
    _assert_matches("203.0.113.8 - - [06/Aug/2026:06:20:14 +0000] POST /api/auth/login 401", None)


def test_unrelated_wpfy_event_log_rejected():
    # events.jsonl style record from another WPFY subsystem.
    _assert_matches(
        '{"timestamp":"2026-08-06T06:20:14Z","action":"login_shield.fail2ban_ensured",'
        '"outcome":"ok","detail":"version=1.0.0"}',
        None,
    )
    # nginx access log entry.
    _assert_matches(
        '203.0.113.8 - - [06/Aug/2026:06:20:14 +0000] "GET /wp-login.php HTTP/1.1" 200 123',
        None,
    )


def test_private_ip_record_matches():
    # fail2ban does not auto-allowlist private networks (plan constraint);
    # only loopback + ::1 are in ignoreip. A private client that reached the
    # panel (not redacted upstream) is bannable.
    _assert_matches(_record(client_ip="10.0.0.5"), "10.0.0.5")


def test_long_username_record_still_matches():
    # Phase 12 filter fixture: a very long username is hashed upstream into
    # the fixed-length account_hash, so the record is a genuine failure and
    # must match, extracting the resolved client IP (never the username).
    long_name = "user" + "A" * 4096
    hash_value = hashlib.sha256(long_name.encode("utf-8")).hexdigest()
    _assert_matches(_record(account_hash=f"sha256:{hash_value}"), _V4)


def test_oversized_identity_fields_rejected():
    # A raw oversized value in a constrained field cannot smuggle a second
    # record: the strict fixed schema rejects non-64-hex hashes.
    _assert_matches(_record(account_hash="sha256:" + "a" * 1024), None)
    _assert_matches(_record(account_hash="sha256:" + "a" * 63), None)


# ---------------------------------------------------------------------------
# Jail config
# ---------------------------------------------------------------------------


def test_panel_jail_enabled_with_policy():
    content = f2b_host.panel_jail_content()
    assert "[wpfy-panel-auth]" in content
    assert "enabled = true" in content
    assert "filter = wpfy-panel-auth" in content
    assert f"findtime = {f2b_host.PANEL_JAIL['findtime']}" in content
    assert f"maxretry = {f2b_host.PANEL_JAIL['maxretry']}" in content
    assert f"bantime = {f2b_host.PANEL_JAIL['bantime']}" in content
    assert f2b_host.PANEL_JAIL == {"findtime": "10m", "maxretry": "8", "bantime": "15m"}


def test_panel_jail_logpath_points_at_panel_auth_log():
    content = f2b_host.panel_jail_content()
    expected = f2b_host._panel_auth_log_path()
    assert f"logpath = {expected}" in content


def test_panel_jail_single_logpath_contract():
    """Blocker 2 guard: the panel jail renders exactly one logpath key."""
    content = f2b_host.panel_jail_content()
    ok, msg = f2b_host.validate_jail_logpath(content)
    assert ok is True, msg
    logpath_lines = [
        line for line in content.splitlines() if line.lstrip().startswith("logpath")
    ]
    assert len(logpath_lines) == 1


def test_panel_jail_ignoreip_only_loopback():
    content = f2b_host.panel_jail_content()
    line = next(line for line in content.splitlines() if line.strip().startswith("ignoreip"))
    values = line.split("=", 1)[1].strip().split()
    assert values == ["127.0.0.0/8", "::1"]
    assert values == list(f2b_host.SAFE_ALLOWLIST)


def test_panel_jail_uses_wpfy_docker_action_unique_chain():
    content = f2b_host.panel_jail_content()
    assert "action = wpfy-docker-http[name=panel-auth]" in content
    from wpfy import fail2ban_docker

    chain = fail2ban_docker.CHAIN_PREFIX + "panel-auth"
    assert chain == "f2b-wpfy-panel-auth"
    fail2ban_docker.validate_chain_name(chain)
    # The panel jail chain must be unique vs the per-site naming contract.
    fail2ban_docker.validate_unique_chain_names(["f2b-wpfy-panel-auth", "f2b-wpfy-somedomain"])


def test_panel_jail_has_backend():
    assert "backend = auto" in f2b_host.panel_jail_content()


# ---------------------------------------------------------------------------
# Filter content rendering
# ---------------------------------------------------------------------------


def test_filter_content_has_real_failregex_not_placeholder():
    content = f2b_host.panel_filter_content()
    assert content.startswith(f2b_host._MANAGED_HEADER)
    assert "[Definition]" in content
    assert "datepattern = {NONE}" in content
    assert "# Phase 12 (t12) defines" not in content
    failregex = _panel_failregex()
    assert "panel_auth_failure" in failregex
    assert "(?P<ip4>" in failregex
    assert "(?P<ip6>" in failregex
    assert "(?P<host>" not in failregex
    # The never-ban sentinel rejection is part of the pattern.
    assert "0\\.0\\.0\\.0" in failregex
    # Regex compiles under fail2ban 1.0 single-line semantics + failure-id guard.
    re.compile(failregex, _F2B_FLAGS)


# ---------------------------------------------------------------------------
# ensure_fail2ban_host integration
# ---------------------------------------------------------------------------


@pytest.fixture
def f2b_module(tmp_wpfy_home, monkeypatch):
    importlib.reload(f2b_host)
    return f2b_host


class _Proc:
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def _healthy_run(command, state):
    if command[0] == "apt-get":
        if "remove" in command:
            state["installed"] = False
            return _Proc(stdout="removed")
        state["installed"] = True
        return _Proc(stdout="installed")
    if command[0] == "systemctl":
        return _Proc(stdout="enabled")
    if command == ["fail2ban-client", "ping"]:
        return _Proc(stdout="Server replied: pong")
    if command == ["fail2ban-client", "-t"]:
        return _Proc(stdout="config ok")
    if command == ["fail2ban-client", "reload"]:
        return _Proc(stdout="reloaded")
    if command == ["fail2ban-client", "version"]:
        return _Proc(stdout="1.0.0")
    return _Proc()


def _binary_present(f2b_module, monkeypatch, state):
    def which(binary):
        if binary == "fail2ban-client":
            return "/usr/bin/fail2ban-client" if state["installed"] else None
        return "/usr/bin/" + binary

    monkeypatch.setattr(f2b_module.shutil, "which", which)


def _run_ensure(f2b_module, monkeypatch, state=None):
    state = state if state is not None else {"installed": True}
    _binary_present(f2b_module, monkeypatch, state)
    monkeypatch.setattr(
        f2b_module.subprocess,
        "run",
        lambda command, **kwargs: _healthy_run(command, state),
    )
    return f2b_module.ensure_fail2ban_host()


def test_ensure_writes_real_panel_filter_and_jail(f2b_module, monkeypatch):
    monkeypatch.setenv("WPFY_TEST_IPV6_CAPABLE", "0")
    result = _run_ensure(f2b_module, monkeypatch)
    assert result.exit_code == 0

    root = f2b_module._fail2ban_root()
    filter_file = root / "filter.d" / "wpfy-panel-auth.conf"
    filter_text = filter_file.read_text(encoding="utf-8")
    assert "panel_auth_failure" in filter_text
    assert "(?P<ip4>" in filter_text
    assert "(?P<ip6>" in filter_text
    assert "(?P<host>" not in filter_text
    assert "0\\.0\\.0\\.0" in filter_text

    jail_text = (root / "jail.d" / "wpfy-panel-auth.local").read_text(encoding="utf-8")
    assert "enabled = true" in jail_text
    assert "logpath = " in jail_text
    assert "action = wpfy-docker-http[name=panel-auth]" in jail_text


def test_ensure_emits_panel_fail2ban_ban_on_activation_once(f2b_module, monkeypatch):
    from wpfy import events

    _run_ensure(f2b_module, monkeypatch)
    bans = [e for e in events.list_events() if e["action"] == "login_shield.panel_fail2ban_ban"]
    assert len(bans) == 1
    assert bans[0]["outcome"] == "ok"
    assert "wpfy-panel-auth" in bans[0]["detail"]
    assert "f2b-wpfy-panel-auth" in bans[0]["detail"]

    # Idempotent re-run: no change, no duplicate activation event.
    _run_ensure(f2b_module, monkeypatch)
    bans = [e for e in events.list_events() if e["action"] == "login_shield.panel_fail2ban_ban"]
    assert len(bans) == 1


# ---------------------------------------------------------------------------
# fail2ban-regex CLI (live tool; skipped on macOS, scheduled live at t21)
# ---------------------------------------------------------------------------


def test_fail2ban_regex_cli_when_available(tmp_path):
    if shutil.which("fail2ban-regex") is None:
        pytest.skip("fail2ban-regex not installed; live run scheduled at t21")

    filter_file = tmp_path / "wpfy-panel-auth.conf"
    filter_file.write_text(f2b_host.panel_filter_content(), encoding="utf-8")

    valid_log = tmp_path / "valid.log"
    valid_log.write_text(
        "\n".join([_record(client_ip=_V4), _record(client_ip=_V6)]) + "\n",
        encoding="utf-8",
    )
    proc = subprocess.run(
        ["fail2ban-regex", str(valid_log), str(filter_file)],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stderr
    assert re.search(r"Failregex:\s*2\s+total", proc.stdout), proc.stdout

    bad_log = tmp_path / "bad.log"
    bad_log.write_text(
        "\n".join([
            _record(client_ip="0.0.0.0"),
            _record(event="panel_auth_success"),
            '{"timestamp":"2026-08-06T06:20:14Z","event":"panel_auth_failure"',
        ]) + "\n",
        encoding="utf-8",
    )
    proc = subprocess.run(
        ["fail2ban-regex", str(bad_log), str(filter_file)],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stderr
    assert re.search(r"Failregex:\s*0\s+total", proc.stdout), proc.stdout
