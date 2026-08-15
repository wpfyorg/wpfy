"""End-to-end panel Login Shield chain harness (t14).

Proves the full chain offline, no real runtime required:

    simulated attack over POST /api/auth/login (trusted-proxy resolution)
    -> JSONL failure records in panel-auth.log
    -> strict filter match (fail2ban_host.panel_failregex)
    -> jail increment (PANEL_JAIL policy: maxretry/findtime, ignoreip)
    -> ban activation by executing the real WPFY Docker action against a
       FakeFirewall-style iptables model
    -> HTTP blocked for the attacker (REJECT in f2b-wpfy-panel-auth behind
       the DOCKER-USER jump)
    -> unban restores HTTP and panel login recovers.

The action is executed only in its IPv4 render (the render the panel jail
gets on hosts without public IPv6, and the render `install_action` produces
under WPFY_TEST_IPV6_CAPABLE=0): single-line actionban/actionunban, no shell
conditionals. The chain model is faithful for that render.

Covers Phase 12 panel tests (login-shield-plan.md 1176-1198) items 1-20 plus
the ``login_shield.panel_fail2ban_ban`` activation event.
"""

from __future__ import annotations

import hashlib
import http.client
import json
import re
import shlex
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

import pytest

from tests.fail2ban_harness import compile_failregex, extract_fid

# A stable non-loopback attacker behind a trusted edge (TEST-NET-3).
ATTACKER = "203.0.113.55"
PROXY = "127.0.0.1"


@pytest.fixture(autouse=True)
def _offline_panel(monkeypatch):
    """Keep every runtime shell-out and discovery deterministic and offline."""
    import wpfy.panel as panel
    import wpfy.panel_auth as panel_auth

    monkeypatch.setattr(panel_auth, "_discover_never_ban_edge_cidrs", lambda: ())
    # Simulate the real deployment: the panel loopback peer is the trusted
    # Traefik edge, so X-Forwarded-For is believed and the attacker IP is
    # resolved (never the proxy).
    monkeypatch.setattr(panel, "trusted_edge_networks", lambda: ("127.0.0.1/32",))


@pytest.fixture
def chain_home(tmp_path, monkeypatch):
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


@pytest.fixture
def fake_clock(monkeypatch):
    """Deterministic clock for lockout / cooldown / expiry assertions."""
    import wpfy.panel_auth as panel_auth

    clock = {"now": 1_000_000.0}
    monkeypatch.setattr(panel_auth.time, "time", lambda: clock["now"])
    return clock


# ---------------------------------------------------------------------------
# HTTP harness
# ---------------------------------------------------------------------------


def _start_server(chain_home, token="bootstrap-run-token"):
    import wpfy.panel as panel

    config = panel.PanelConfig(host="127.0.0.1", port=0, token=token)
    server = panel.make_panel_server(config)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    return server, thread, host, port, token


def _stop_server(server, thread):
    server.shutdown()
    server.server_close()
    thread.join(timeout=5)


def _request(host, port, path, *, method="GET", token=None, body=None, headers=None):
    request_headers = dict(headers or {})
    if token is not None:
        request_headers["Authorization"] = f"Bearer {token}"
    payload = None
    if body is not None:
        payload = json.dumps(body).encode("utf-8")
        request_headers["Content-Type"] = "application/json"
    connection = http.client.HTTPConnection(host, port, timeout=15)
    try:
        connection.request(method, path, body=payload, headers=request_headers)
        response = connection.getresponse()
        raw = response.read().decode("utf-8")
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            parsed = raw
        lowered = {name.lower(): value for name, value in response.getheaders()}
        return response.status, parsed, lowered
    finally:
        connection.close()


def _post_login(host, port, username, password, *, xff=ATTACKER, totp=None, headers=None):
    request_headers = dict(headers or {})
    if xff is not None:
        request_headers["X-Forwarded-For"] = xff
    body = {"username": username, "password": password}
    if totp is not None:
        body["totp"] = totp
    return _request(
        host, port, "/api/auth/login", method="POST",
        body=body,
        headers=request_headers,
    )


# ---------------------------------------------------------------------------
# Chain model: FakeFirewall-style iptables model + fail2ban jail model
# ---------------------------------------------------------------------------


class FirewallModel:
    """Ordered-chain model of the iptables commands the WPFY action renders."""

    def __init__(self, docker_user_rules=()):
        self.chains = {"DOCKER-USER": list(docker_user_rules)}
        self.creation_order = []

    def run(self, argv):
        argv = [a for a in argv if a != "-w"]
        if not argv:
            return 0, ""
        if argv[0] in ("iptables", "ip6tables"):
            argv = argv[1:]
        if not argv:
            return 0, ""
        op = argv[0]
        if op == "-N":
            name = argv[1]
            if name not in self.chains:
                self.chains[name] = []
                self.creation_order.append(name)
            return 0, ""
        if op == "-F":
            name = argv[1]
            if name not in self.chains:
                return 1, ""
            self.chains[name] = []
            return 0, ""
        if op == "-C":
            target = argv[1]
            rule = " ".join(argv[2:])
            return (0, "") if rule in self.chains.get(target, []) else (1, "")
        if op == "-I":
            target = argv[1]
            if target not in self.chains:
                return 1, ""
            rest = argv[2:]
            position = 1
            if rest and rest[0].isdigit():
                position = int(rest[0])
                rest = rest[1:]
            rule = " ".join(rest)
            position = min(max(position - 1, 0), len(self.chains[target]))
            self.chains[target].insert(position, rule)
            return 0, ""
        if op == "-D":
            target = argv[1]
            if target not in self.chains:
                return 1, ""
            rule = " ".join(argv[2:])
            try:
                self.chains[target].remove(rule)
            except ValueError:
                return 1, ""
            return 0, ""
        if op == "-X":
            name = argv[1]
            if name not in self.chains:
                return 0, ""
            if self.chains[name]:
                return 1, ""
            del self.chains[name]
            return 0, ""
        if op == "-S":
            name = argv[1]
            if name not in self.chains:
                return 1, ""
            lines = [f"-N {name}"] + list(self.chains[name])
            return 0, "\n".join(lines) + "\n"
        if op == "-L":
            name = argv[1]
            if name not in self.chains:
                return 1, ""
            return 0, "\n".join(self.chains[name]) + "\n"
        return 1, ""


_SECTION_RE = re.compile(r"^(action\w+)\s*=\s*(.*)$")


def _section_lines(content, section):
    """Extract executable command lines from one rendered action section."""
    out = []
    current = None
    for raw in content.splitlines():
        stripped = raw.strip()
        match = _SECTION_RE.match(stripped)
        if match:
            current = match.group(1)
            body = match.group(2).strip()
            if current == section and body and not body.startswith("#"):
                out.append(body)
            continue
        if current == section and stripped and not stripped.startswith("#"):
            out.append(stripped)
    return out


def _shell_tokens(line):
    line = line.replace("2>/dev/null", "").replace("2>&1", "").replace(">/dev/null", "")
    try:
        return shlex.split(line)
    except ValueError:
        return []


def _shell_exec(line, fw):
    line = line.strip()
    if not line or line.startswith("#"):
        return 0
    if "||" in line:
        rc = 1
        for part in (p.strip() for p in line.split("||")):
            if part == "true":
                rc = 0
                break
            if _shell_exec(part, fw) == 0:
                rc = 0
                break
        return rc
    argv = _shell_tokens(line)
    if not argv:
        return 0
    return fw.run(argv)[0]


def _run_section(fw, content, section):
    for line in _section_lines(content, section):
        _shell_exec(line, fw)
    return fw


def _render_panel_action(attacker_ip):
    """Render the real panel jail action and substitute fail2ban tags."""
    import wpfy.fail2ban_docker as fail2ban_docker
    import wpfy.fail2ban_host as fail2ban_host

    content = fail2ban_docker.action_content(
        chain=fail2ban_host.PANEL_JAIL_CHAIN, ipv6=False
    )
    return content.replace("<ip>", attacker_ip).replace("<name>", "panel-auth")


def _banned_firewall(attacker_ip=ATTACKER, seed=()):
    """Run actionstart + actionban for the panel jail; returns (fw, content)."""
    content = _render_panel_action(attacker_ip)
    fw = FirewallModel(docker_user_rules=seed)
    _run_section(fw, content, "actionstart")
    _run_section(fw, content, "actionban")
    return fw, content


def _traffic_blocked(fw, chain, ip, port):
    """True when a REJECT rule in the WPFY chain blocks ip on the port."""
    if chain not in fw.chains:
        return False
    for rule in fw.chains[chain]:
        if "-j REJECT" not in rule:
            continue
        tokens = rule.split()
        if "-s" in tokens:
            index = tokens.index("-s")
            if tokens[index + 1] != ip:
                continue
        if "--dports" in tokens:
            index = tokens.index("--dports")
            if str(port) not in tokens[index + 1].split(","):
                continue
        return True
    return False


def _duration_seconds(value: str) -> float:
    value = str(value).strip().lower()
    return int(value[:-1]) * {"s": 1, "m": 60, "h": 3600, "d": 86400}[value[-1]]


def _ip_in_networks(address: str, networks: tuple[str, ...]) -> bool:
    import ipaddress

    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        return False
    for raw in networks:
        try:
            network = ipaddress.ip_network(raw, strict=False)
        except ValueError:
            continue
        if parsed.version == network.version and parsed in network:
            return True
    return False


class PanelJailModel:
    """Faithful offline model of the wpfy-panel-auth jail (fail2ban semantics).

    Reads the raw lines the panel writer emitted, matches them with the real
    strict filter regex, counts matched failures per extracted host inside the
    real findtime, skips ignoreip members, and bans when maxretry is reached.
    """

    def __init__(self, jail_content, failregex, now):
        policy = {}
        for key in ("findtime", "maxretry", "bantime"):
            match = re.search(rf"^{key}\s*=\s*(\S+)", jail_content, re.MULTILINE)
            policy[key] = match.group(1) if match else None
        match = re.search(r"^ignoreip\s*=\s*(.*)$", jail_content, re.MULTILINE)
        policy["ignoreip"] = tuple(match.group(1).split()) if match else ()
        self.policy = policy
        self.failregex = failregex
        self.now = now
        self.findtime = _duration_seconds(policy["findtime"])
        self.maxretry = int(policy["maxretry"])
        self.ignoreip = policy["ignoreip"]
        self.counts: dict[str, tuple[int, float]] = {}
        self.bans: dict[str, float] = {}

    def ingest_lines(self, lines: list[str]) -> "PanelJailModel":
        for line in lines:
            line = line.strip()
            if not line:
                continue
            match = self.failregex.match(line)
            if match is None:
                continue
            host = extract_fid(match)
            if _ip_in_networks(host, self.ignoreip):
                continue
            try:
                record = json.loads(line)
                epoch = datetime.strptime(
                    record["timestamp"], "%Y-%m-%dT%H:%M:%SZ"
                ).replace(tzinfo=timezone.utc).timestamp()
            except (ValueError, KeyError, TypeError, json.JSONDecodeError):
                continue
            count, latest = self.counts.get(host, (0, 0.0))
            if self.now - epoch <= self.findtime:
                count += 1
            else:
                count = 1
            self.counts[host] = (count, epoch)
            if count >= self.maxretry and host not in self.bans:
                self.bans[host] = self.now
        return self

    def banned_ips(self) -> set[str]:
        return set(self.bans)


# ---------------------------------------------------------------------------
# Helpers for the evidence flow
# ---------------------------------------------------------------------------


def _read_log(log_dir: str) -> list[str]:
    path = Path(log_dir) / "panel-auth.log"
    if not path.exists():
        return []
    return [line for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def _read_log_records(log_dir: str) -> list[dict]:
    return [json.loads(line) for line in _read_log(log_dir)]


def _expected_hash(username: str) -> str:
    return "sha256:" + hashlib.sha256(username[:64].encode("utf-8")).hexdigest()


def _panel_failregex():
    import wpfy.fail2ban_host as fail2ban_host

    return compile_failregex(fail2ban_host.panel_failregex())


def _panel_jail_model(log_dir, now):
    import wpfy.fail2ban_host as fail2ban_host

    return PanelJailModel(
        fail2ban_host.panel_jail_content(),
        _panel_failregex(),
        now,
    )


def _add_user(username="admin", password="admin-password"):
    import wpfy.panel_auth as panel_auth

    panel_auth.add_user(username, password, role=panel_auth.ROLE_ADMIN)


def _attack(host, port, username="admin", password="wrong", *, n=8, attacker=ATTACKER):
    """Simulate n failed login attempts from the attacker over HTTP."""
    statuses = []
    for _ in range(n):
        status, _, _ = _post_login(host, port, username, password, xff=attacker)
        statuses.append(status)
    return statuses


# ---------------------------------------------------------------------------
# Chain: attack -> log -> filter -> jail -> ban -> blocked -> unban
# ---------------------------------------------------------------------------


def test_chain_attack_emits_records_and_filter_extracts_attacker(chain_home):
    # Items 1, 2, 8, 15: every failed login emits a valid record; below-lockout
    # failures are all logged; the resolved attacker IP (not the proxy) is the
    # recorded client; usernames cannot inject extra lines.
    import wpfy.panel_auth as panel_auth

    _add_user("admin", "admin-password")
    server, thread, host, port, _ = _start_server(chain_home)
    try:
        statuses = _attack(host, port, n=3)
        assert statuses == [401, 401, 401]

        records = _read_log_records(chain_home.log_dir)
        assert len(records) == 3
        for record in records:
            assert set(record) == {
                "timestamp", "event", "surface", "client_ip", "account_hash", "reason_class",
            }
            assert record["event"] == "panel_auth_failure"
            assert record["surface"] == "password"
            assert record["client_ip"] == ATTACKER
            assert record["account_hash"] == _expected_hash("admin")
            assert record["reason_class"] == "invalid_credentials"
            assert PROXY not in record["client_ip"]

        # The strict filter matches every real record and extracts the
        # attacker, so the jail sees the real client, never the proxy.
        failregex = _panel_failregex()
        for record in records:
            line = json.dumps(record, ensure_ascii=True, separators=(",", ":"))
            match = failregex.match(line)
            assert match is not None
            assert extract_fid(match) == ATTACKER

        # Injection username produces exactly one more valid line and no raw
        # attacker-controlled bytes in the log.
        evil = 'evil"}\n{"event":"x'
        status, _, _ = _post_login(host, port, evil, "wrong")
        assert status == 401
        raw_lines = _read_log(chain_home.log_dir)
        assert len(raw_lines) == 4
        assert evil not in raw_lines[-1]
        assert json.loads(raw_lines[-1])["account_hash"] == _expected_hash("")
        assert PROXY not in raw_lines[-1]
    finally:
        _stop_server(server, thread)


def test_chain_success_never_matches_filter(chain_home):
    # Item 3: successful logins emit nothing and therefore cannot match the
    # failure filter.
    import wpfy.panel_auth as panel_auth

    _add_user("admin", "admin-password")
    server, thread, host, port, _ = _start_server(chain_home)
    try:
        status, body, _ = _post_login(host, port, "admin", "admin-password")
        assert status == 200
        assert "token" in body
        assert _read_log(chain_home.log_dir) == []

        jail = _panel_jail_model(chain_home.log_dir, now=time.time())
        jail.ingest_lines(_read_log(chain_home.log_dir))
        assert jail.banned_ips() == set()
        assert jail.counts == {}
    finally:
        _stop_server(server, thread)


def test_chain_account_lockout_and_client_throttle_remain_active(chain_home, monkeypatch, fake_clock):
    # Items 4, 5, 18: per-account lockout and per-client throttling both stay
    # active with correct Retry-After, and neither reveals counters.
    import wpfy.panel_auth as panel_auth

    _add_user("u1", "password-one")
    _add_user("u2", "password-two")
    monkeypatch.setattr(panel_auth, "MAX_CLIENT_FAILURES", 2)
    monkeypatch.setattr(panel_auth, "CLIENT_COOLDOWN_SECONDS", 60)
    monkeypatch.setattr(panel_auth, "MAX_LOGIN_FAILURES", 2)
    server, thread, host, port, _ = _start_server(chain_home)
    try:
        # Per-client throttle (item 5): 2 failures -> the crossing failure
        # itself returns 429; even a correct password stays 429 with
        # Retry-After (existing threshold semantics preserved).
        status, _, _ = _post_login(host, port, "u1", "wrong", xff="203.0.113.70")
        assert status == 401
        status, _, _ = _post_login(host, port, "u1", "wrong", xff="203.0.113.70")
        assert status == 429
        status, _, headers = _post_login(host, port, "u1", "password-one", xff="203.0.113.70")
        assert status == 429
        assert headers.get("retry-after") == "60"
        status, body, _ = _post_login(host, port, "u1", "password-one", xff="203.0.113.70")
        assert status == 429
        assert set(body.keys()) <= {"error"}
        assert "counter" not in json.dumps(body).lower()

        # Per-account lockout (item 4): after 2 failures the account is
        # locked; even a correct password from a fresh (unthrottled) client
        # is refused with the locked reason and a generic body.
        fake_clock["now"] += 60  # clear the u1 client cooldown window
        status, _, _ = _post_login(host, port, "u2", "wrong", xff="203.0.113.71")
        assert status == 401
        status, _, _ = _post_login(host, port, "u2", "wrong", xff="203.0.113.71")
        assert status == 429
        status, _, _ = _post_login(host, port, "u2", "password-two", xff="203.0.113.72")
        assert status == 401
        records = _read_log_records(chain_home.log_dir)
        assert [record["reason_class"] for record in records[-3:]] == [
            "invalid_credentials", "invalid_credentials", "locked",
        ]
    finally:
        _stop_server(server, thread)


def test_chain_blocked_requests_skip_password_verification(chain_home, monkeypatch, fake_clock):
    # Item 6: while a client is throttled (or an account locked), the request
    # path must NOT run the expensive password verification.
    import wpfy.panel_auth as panel_auth

    _add_user("u1", "password-one")
    _add_user("u2", "password-two")
    monkeypatch.setattr(panel_auth, "MAX_CLIENT_FAILURES", 2)
    monkeypatch.setattr(panel_auth, "CLIENT_COOLDOWN_SECONDS", 60)
    monkeypatch.setattr(panel_auth, "MAX_LOGIN_FAILURES", 2)
    calls = {"n": 0}
    real_verify = panel_auth.verify_password

    def counting_verify(username, password):
        calls["n"] += 1
        return real_verify(username, password)

    monkeypatch.setattr(panel_auth, "verify_password", counting_verify)
    server, thread, host, port, _ = _start_server(chain_home)
    try:
        _post_login(host, port, "u1", "wrong", xff="203.0.113.80")
        _post_login(host, port, "u1", "wrong", xff="203.0.113.80")
        assert calls["n"] == 2
        # Throttled: correct password refused without verification.
        status, _, _ = _post_login(host, port, "u1", "password-one", xff="203.0.113.80")
        assert status == 429
        assert calls["n"] == 2

        fake_clock["now"] += 60
        # Locked account: correct password from a fresh client is refused
        # without verification.
        _post_login(host, port, "u2", "wrong", xff="203.0.113.81")
        _post_login(host, port, "u2", "wrong", xff="203.0.113.81")
        assert calls["n"] == 4
        status, _, _ = _post_login(host, port, "u2", "password-two", xff="203.0.113.82")
        assert status == 401
        assert calls["n"] == 4
    finally:
        _stop_server(server, thread)


def test_chain_fail2ban_threshold_activates_ban_and_blocks_http(chain_home):
    # Items 7, 8: N failures -> jail ban activates in the FakeFirewall-style
    # model of the WPFY action; the real attacking client (not the proxy) is
    # blocked on HTTP/HTTPS only; SSH is untouched.
    import wpfy.fail2ban_host as fail2ban_host

    _add_user("admin", "admin-password")
    server, thread, host, port, _ = _start_server(chain_home)
    try:
        statuses = _attack(host, port, n=8)
        assert all(status == 401 for status in statuses)
        raw_lines = _read_log(chain_home.log_dir)
        assert len(raw_lines) == 8

        # Jail increments: maxretry reached inside findtime -> ban.
        jail = _panel_jail_model(chain_home.log_dir, now=time.time())
        jail.ingest_lines(raw_lines)
        assert jail.counts[ATTACKER][0] == 8
        assert ATTACKER in jail.banned_ips()
        assert int(jail.policy["maxretry"]) == 8
        assert jail.policy["findtime"] == "10m"
        assert jail.ignoreip == ("127.0.0.0/8", "::1")

        # Ban activation via the WPFY Docker action (executed, not mocked).
        fw, _ = _banned_firewall(ATTACKER)
        chain = fail2ban_host.PANEL_JAIL_CHAIN
        assert fw.chains["DOCKER-USER"][0] == f"-j {chain}"
        assert fw.chains[chain]
        assert any(f"-s {ATTACKER}" in rule and "--dports 80,443" in rule for rule in fw.chains[chain])

        # HTTP blocked, HTTPS blocked, SSH untouched, unrelated port untouched.
        assert _traffic_blocked(fw, chain, ATTACKER, 80)
        assert _traffic_blocked(fw, chain, ATTACKER, 443)
        assert not _traffic_blocked(fw, chain, ATTACKER, 22)
        assert not _traffic_blocked(fw, chain, ATTACKER, 8080)

        # The proxy (trusted edge) is never the blocked entity.
        assert not any("-s 127.0.0.1" in rule or "-s 127.0.0.0" in rule for rule in fw.chains[chain])
        assert not _traffic_blocked(fw, chain, PROXY, 80)
    finally:
        _stop_server(server, thread)


def test_chain_panel_restart_does_not_remove_active_ban(chain_home):
    # Item 9: host-level bans persist independent of the panel; a panel
    # restart (fresh server + reset in-memory state) cannot remove them.
    import wpfy.fail2ban_host as fail2ban_host

    _add_user("admin", "admin-password")
    fw, content = _banned_firewall(ATTACKER)
    chain = fail2ban_host.PANEL_JAIL_CHAIN
    assert _traffic_blocked(fw, chain, ATTACKER, 80)

    server, thread, host, port, _ = _start_server(chain_home)
    try:
        # Panel restart: stop, wipe in-memory state, start a fresh server.
        _stop_server(server, thread)
        import wpfy.panel_auth as panel_auth

        panel_auth.reset_state()
        server, thread, host, port, _ = _start_server(chain_home)

        # The ban lives in the firewall model, untouched by the panel restart.
        assert _traffic_blocked(fw, chain, ATTACKER, 80)
        assert "-j f2b-wpfy-panel-auth" in fw.chains["DOCKER-USER"]

        # Even a fail2ban reload (actionstart re-run) flushes and re-issues
        # the ban from the fail2ban ban table -> still blocked.
        _run_section(fw, content, "actionstart")
        _run_section(fw, content, "actionban")
        assert _traffic_blocked(fw, chain, ATTACKER, 80)
    finally:
        _stop_server(server, thread)


def test_chain_fail2ban_unavailable_keeps_in_memory_throttling(chain_home, monkeypatch, fake_clock):
    # Item 10: fail2ban failure must not disable in-memory throttling.
    # The panel login path is independent of the fail2ban layer; with
    # fail2ban absent, throttling still returns 429 + Retry-After.
    import wpfy.fail2ban_host as fail2ban_host
    import wpfy.panel_auth as panel_auth

    _add_user("admin", "admin-password")
    # Deterministically model fail2ban unavailable on this host.
    monkeypatch.setattr(fail2ban_host.shutil, "which", lambda _binary: None)
    assert fail2ban_host._fail2ban_installed() is False

    monkeypatch.setattr(panel_auth, "MAX_CLIENT_FAILURES", 2)
    monkeypatch.setattr(panel_auth, "CLIENT_COOLDOWN_SECONDS", 60)
    server, thread, host, port, _ = _start_server(chain_home)
    try:
        _post_login(host, port, "admin", "wrong", xff="203.0.113.90")
        status, _, _ = _post_login(host, port, "admin", "wrong", xff="203.0.113.90")
        assert status == 429
        status, _, headers = _post_login(host, port, "admin", "wrong", xff="203.0.113.90")
        assert status == 429
        assert headers.get("retry-after") == "60"
    finally:
        _stop_server(server, thread)


def test_chain_totp_failure_covered(chain_home):
    # Item 11: TOTP failures emit records the filter matches.
    import wpfy.panel_auth as panel_auth

    _add_user("admin", "admin-password")
    panel_auth.enable_totp("admin")
    server, thread, host, port, _ = _start_server(chain_home)
    try:
        status, _, _ = _post_login(host, port, "admin", "admin-password", totp="000000")
        assert status == 401
        records = _read_log_records(chain_home.log_dir)
        assert len(records) == 1
        assert records[0]["reason_class"] == "totp_failed"
        failregex = _panel_failregex()
        match = failregex.match(json.dumps(records[0], ensure_ascii=True, separators=(",", ":")))
        assert match is not None
        assert extract_fid(match) == ATTACKER
    finally:
        _stop_server(server, thread)


def test_chain_no_recovery_or_password_reset_surface(chain_home):
    # Items 12, 13: recovery-code verification and password-reset surfaces are
    # not supported by the panel; no route exists, so there is nothing to log
    # or protect (documented N/A).
    import wpfy.panel as panel
    import wpfy.panel_auth as panel_auth

    auth_patterns = [
        route.pattern.pattern
        for route in (*panel._SETUP_ROUTES, *panel._ROUTES)
        if "/auth/" in route.pattern.pattern or "/setup" in route.pattern.pattern
    ]
    blob = " ".join(auth_patterns)
    assert blob
    for needle in ("recovery", "recover", "reset", "forgot", "password"):
        assert needle not in blob
    for surface in ("recovery", "password_reset"):
        assert not hasattr(panel_auth, surface)
        assert not hasattr(panel_auth, f"verify_{surface}")


def test_chain_no_account_enumeration(chain_home):
    # Item 14: generic errors; known and unknown accounts are
    # indistinguishable (no enumeration introduced).
    _add_user("admin", "admin-password")
    server, thread, host, port, _ = _start_server(chain_home)
    try:
        status, body_known, _ = _post_login(host, port, "admin", "wrong")
        status2, body_unknown, _ = _post_login(host, port, "no-such-user", "wrong")
        assert status == status2 == 401
        assert body_known == body_unknown == {"error": "invalid credentials"}
    finally:
        _stop_server(server, thread)


def test_chain_state_remains_bounded(chain_home, monkeypatch, fake_clock):
    # Item 16: in-memory failure state is bounded by distinct identities and
    # pruned on expiry, never by attempt volume.
    import wpfy.panel_auth as panel_auth

    monkeypatch.setattr(panel_auth, "MAX_CLIENT_FAILURES", 10)

    # Unknown-account attempts only move the per-client counter; 3 clients x
    # 12 attempts stays 3 entries, each count capped at MAX_CLIENT_FAILURES.
    for client in ("203.0.113.10", "203.0.113.11", "203.0.113.12"):
        for index in range(12):
            panel_auth.login(f"ghost-{client}-{index}", "wrong", client=client)
    assert len(panel_auth._CLIENT_FAILURES) == 3
    assert all(
        panel_auth._CLIENT_FAILURES[client].count <= 10
        for client in ("203.0.113.10", "203.0.113.11", "203.0.113.12")
    )

    # 100 attempts from one client stays one entry, count capped.
    for index in range(100):
        panel_auth.login(f"ghost-single-{index}", "wrong", client="203.0.113.13")
    assert len(panel_auth._CLIENT_FAILURES) == 4
    assert panel_auth._CLIENT_FAILURES["203.0.113.13"].count <= 10

    # Account failures bounded by distinct usernames (one locked account).
    panel_auth.add_user("u1", "password-one", role=panel_auth.ROLE_ADMIN)
    for _ in range(40):
        panel_auth.login("u1", "wrong", client="203.0.113.20")
    assert set(panel_auth._LOGIN_FAILURES) == {"u1"}

    # Expiry prunes the client state.
    fake_clock["now"] += 61
    assert panel_auth.client_throttled("203.0.113.13") is False
    assert panel_auth._CLIENT_FAILURES == {}
    assert panel_auth.client_retry_after("203.0.113.13") == 0


def test_chain_concurrent_attempts_cannot_bypass_counters(chain_home):
    # Item 17: threaded attempts cannot lose records or bypass the counters.
    import wpfy.panel_auth as panel_auth

    _add_user("admin", "admin-password")
    server, thread, host, port, _ = _start_server(chain_home)
    try:
        threads = 8
        per_thread = 5
        results: list[tuple[int, str]] = []
        errors: list[BaseException] = []

        def worker(seed: int) -> None:
            try:
                for index in range(per_thread):
                    status, body, _ = _post_login(
                        host, port, f"user-{seed}-{index}", "wrong",
                    )
                    results.append((status, body.get("error", "") if isinstance(body, dict) else ""))
            except BaseException as exc:  # pragma: no cover - failure diagnostic
                errors.append(exc)

        running = [threading.Thread(target=worker, args=(seed,)) for seed in range(threads)]
        for t in running:
            t.start()
        for t in running:
            t.join(timeout=30)

        assert not errors
        assert all(status in {401, 429} for status, _ in results)
        assert len(results) == threads * per_thread

        raw_lines = _read_log(chain_home.log_dir)
        assert len(raw_lines) == threads * per_thread
        records = [json.loads(line) for line in raw_lines]
        failregex = _panel_failregex()
        for record in records:
            assert set(record) == {
                "timestamp", "event", "surface", "client_ip", "account_hash", "reason_class",
            }
            assert record["event"] == "panel_auth_failure"
            assert record["reason_class"] in {"invalid_credentials", "throttled"}
            assert failregex.match(json.dumps(record, ensure_ascii=True, separators=(",", ":"))) is not None

        # The per-client counter engaged: the attacker client is throttled.
        assert panel_auth.client_throttled(ATTACKER) is True
        assert panel_auth.client_retry_after(ATTACKER) > 0
    finally:
        _stop_server(server, thread)


def test_chain_root_inspection_and_unban_restore_login(chain_home, fake_clock):
    # Items 19, 20: an operator (root) can inspect the ban and unban safely;
    # after unban the panel login recovers (cooldown/lockout expired).
    import wpfy.fail2ban_host as fail2ban_host

    _add_user("admin", "admin-password")
    server, thread, host, port, _ = _start_server(chain_home)
    try:
        statuses = _attack(host, port, n=8)
        assert all(status == 401 for status in statuses)
        jail = _panel_jail_model(chain_home.log_dir, now=time.time())
        jail.ingest_lines(_read_log(chain_home.log_dir))
        assert ATTACKER in jail.banned_ips()

        fw, content = _banned_firewall(ATTACKER, seed=["-p tcp --dport 22 -j ACCEPT", "-j RETURN"])
        chain = fail2ban_host.PANEL_JAIL_CHAIN

        # Root can inspect: iptables -S lists the exact ban rule.
        _rc, listing = fw.run(["iptables", "-w", "-S", chain])
        assert _rc == 0
        assert f"-s {ATTACKER}" in listing
        assert "--dports 80,443" in listing
        assert _traffic_blocked(fw, chain, ATTACKER, 80)

        # Unban removes exactly the matching rule; unrelated rules survive.
        _run_section(fw, content, "actionunban")
        assert fw.chains[chain] == []
        assert fw.chains["DOCKER-USER"] == [
            "-j f2b-wpfy-panel-auth",
            "-p tcp --dport 22 -j ACCEPT",
            "-j RETURN",
        ]
        assert not _traffic_blocked(fw, chain, ATTACKER, 80)

        # Login recovers: lockout + client cooldown expired, ban lifted.
        fake_clock["now"] += 600
        status, body, _ = _post_login(host, port, "admin", "admin-password")
        assert status == 200
        assert "token" in body
    finally:
        _stop_server(server, thread)


def test_chain_panel_fail2ban_ban_event_emitted(chain_home, monkeypatch):
    # The jail activation emits login_shield.panel_fail2ban_ban exactly once;
    # the ban event describes the WPFY action and chain used by the chain.
    import wpfy.fail2ban_host as fail2ban_host
    import wpfy.events as events
    import wpfy.fail2ban_docker as fail2ban_docker

    monkeypatch.setenv("WPFY_TEST_IPV6_CAPABLE", "0")
    state = {"installed": True}
    monkeypatch.setattr(
        fail2ban_host.shutil, "which",
        lambda binary: "/usr/bin/fail2ban-client" if binary == "fail2ban-client" and state["installed"] else "/usr/bin/" + binary,
    )

    def healthy_run(command, **_kwargs):
        if command[0] == "apt-get":
            return type("Proc", (), {"returncode": 0, "stdout": "ok", "stderr": ""})()
        if command == ["fail2ban-client", "ping"]:
            return type("Proc", (), {"returncode": 0, "stdout": "Server replied: pong", "stderr": ""})()
        return type("Proc", (), {"returncode": 0, "stdout": "ok", "stderr": ""})()

    monkeypatch.setattr(fail2ban_host.subprocess, "run", healthy_run)

    result = fail2ban_host.ensure_fail2ban_host()
    assert result.exit_code == 0

    bans = [e for e in events.list_events() if e["action"] == "login_shield.panel_fail2ban_ban"]
    assert len(bans) == 1
    assert bans[0]["outcome"] == "ok"
    assert "wpfy-docker-http" in bans[0]["detail"]
    assert fail2ban_host.PANEL_JAIL_CHAIN in bans[0]["detail"]
    assert "maxretry 8" in bans[0]["detail"]

    # Idempotent re-run emits no duplicate activation event.
    fail2ban_host.ensure_fail2ban_host()
    bans = [e for e in events.list_events() if e["action"] == "login_shield.panel_fail2ban_ban"]
    assert len(bans) == 1

    # The ban the chain activates is performed by the same WPFY Docker action
    # on the same chain the event names.
    content = fail2ban_docker.action_content(chain=fail2ban_host.PANEL_JAIL_CHAIN, ipv6=False)
    assert "-I f2b-wpfy-panel-auth 1 -s <ip>" in content
