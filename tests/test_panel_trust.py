from __future__ import annotations

import ipaddress
import time
from pathlib import Path
import pytest

import wpfy.panel as panel
from wpfy.panel import (
    _TRUSTED_EDGE_CACHE,
    _TRUSTED_EDGE_LOCK,
    _TRUSTED_EDGE_TTL_SECONDS,
    _UNKNOWN_CLIENT,
    resolve_client_address,
    trusted_edge_networks,
)


def _clear_cache() -> None:
    with _TRUSTED_EDGE_LOCK:
        panel._TRUSTED_EDGE_CACHE = None


def _set_cache(networks: tuple[str, ...], expires_at: float) -> None:
    with _TRUSTED_EDGE_LOCK:
        panel._TRUSTED_EDGE_CACHE = (networks, expires_at)


def test_ttl_constant_is_30_seconds() -> None:
    # A recreated Traefik with a new container IP must be picked up before
    # the next failed-login attempt; the value is the security contract.
    assert _TRUSTED_EDGE_TTL_SECONDS == 30


def test_fresh_discovery_caches_for_ttl_and_then_refreshes(monkeypatch) -> None:
    _clear_cache()
    calls: list[str] = []

    def fake_discovery(network_name: str) -> tuple[str, ...]:
        calls.append(network_name)
        if len(calls) == 1:
            return ("10.0.0.5/32",)
        return ("10.0.0.99/32",)

    monkeypatch.setattr(panel.traefik, "traefik_network_cidrs", fake_discovery)

    first = trusted_edge_networks()
    assert first == ("10.0.0.5/32",)
    assert len(calls) == 1

    # Second call inside the TTL must reuse the cache and not rediscovery,
    # even if the underlying address would now resolve to something else.
    second = trusted_edge_networks()
    assert second == ("10.0.0.5/32",)
    assert len(calls) == 1

    # Force the cache to look expired without sleeping. We rebuild the slot
    # under the lock with a deadline already in the past.
    with _TRUSTED_EDGE_LOCK:
        panel._TRUSTED_EDGE_CACHE = (("10.0.0.5/32",), time.monotonic() - 1.0)

    third = trusted_edge_networks()
    assert third == ("10.0.0.99/32",), (
        "after TTL expiry the panel must re-discover and pick up Traefik's "
        "new container IP, not return the stale cached value"
    )
    assert len(calls) == 2


def test_failure_is_not_cached(monkeypatch) -> None:
    _clear_cache()
    attempts: list[tuple[str, ...]] = []

    def flaky_discovery(network_name: str) -> tuple[str, ...]:
        attempts.append((network_name,))
        if len(attempts) == 1:
            raise RuntimeError("docker unavailable")
        return ("10.0.0.7/32",)

    monkeypatch.setattr(panel.traefik, "traefik_network_cidrs", flaky_discovery)

    first = trusted_edge_networks()
    assert first == ()
    assert len(attempts) == 1

    # A transient Docker outage must not pin the shared-bucket fallback for
    # the panel's lifetime. The next call must re-attempt discovery.
    second = trusted_edge_networks()
    assert second == ("10.0.0.7/32",)
    assert len(attempts) == 2


def test_uses_monotonic_clock_not_wall_clock(monkeypatch) -> None:
    # time.time() is wall clock and can be set backwards by NTP; that must
    # never extend the cache lifetime. Verify by simulating a wall-clock
    # regression and confirming the cache is still respected.
    _clear_cache()
    monkeypatch.setattr(
        panel.traefik,
        "traefik_network_cidrs",
        lambda _network: ("10.0.0.8/32",),
    )

    real_monotonic = time.monotonic

    class _FrozenClock:
        def __init__(self) -> None:
            self.now = 1000.0

        def __call__(self) -> float:
            return self.now

    clock = _FrozenClock()
    monkeypatch.setattr(panel.time, "monotonic", clock)

    first = trusted_edge_networks()
    assert first == ("10.0.0.8/32",)

    # Roll the wall clock backwards. If the implementation were using
    # time.time() this would push the cache deadline into the past; with
    # monotonic it cannot.
    with _TRUSTED_EDGE_LOCK:
        assert panel._TRUSTED_EDGE_CACHE is not None
        original_deadline = panel._TRUSTED_EDGE_CACHE[1]

    # Move monotonic time backwards too — same hypothetical bug. The
    # invariant we assert is: the implementation reads time only from
    # `panel.time.monotonic` and never from `panel.time.time`. The next
    # call must therefore use the original cache deadline, not be fooled
    # by any wall-clock change.
    clock.now = original_deadline - 10_000.0
    assert clock() < original_deadline  # sanity: the clock went backwards

    second = trusted_edge_networks()
    assert second == ("10.0.0.8/32",), (
        "regression: panel must not consult wall-clock time for cache expiry"
    )

    # Sanity: the deadline we recorded is the only timestamp involved; the
    # implementation never asked time.time() for anything.
    with _TRUSTED_EDGE_LOCK:
        assert panel._TRUSTED_EDGE_CACHE is not None
        assert panel._TRUSTED_EDGE_CACHE[1] == original_deadline

    # Now drive monotonic past the deadline to prove the cache does expire
    # when the chosen clock advances.
    clock.now = original_deadline + 1.0
    real_calls = {"n": 0}

    def real_discovery(_network: str) -> tuple[str, ...]:
        real_calls["n"] += 1
        return ("10.0.0.42/32",)

    monkeypatch.setattr(panel.traefik, "traefik_network_cidrs", real_discovery)
    third = trusted_edge_networks()
    assert third == ("10.0.0.42/32",)
    assert real_calls["n"] == 1


def test_resolve_client_address_never_forges() -> None:
    # Client-IP resolution must never let a peer pin throttling on a victim
    # address: an untrusted peer cannot use a forwarded header, and a trusted
    # peer walks the chain right-to-left past our own hops.
    trusted = ("10.0.0.5/32",)

    # Peer is not the trusted edge: forwarded header is ignored, peer used.
    assert resolve_client_address("203.0.113.7", "198.51.100.10", trusted) == "203.0.113.7"

    # Peer is the trusted edge, forwarded chain walks right-to-left past our
    # own hop, then lands on the first untrusted address.
    assert resolve_client_address(
        "10.0.0.5",
        "198.51.100.10, 10.0.0.5",
        trusted,
    ) == "198.51.100.10"

    # Peer is the trusted edge, no forwarded chain: the proxy's own IP is in
    # the never-ban set, so resolve to the unknown sentinel instead of
    # emitting a ban-triggering record keyed on the edge address.
    assert resolve_client_address("10.0.0.5", None, trusted) == _UNKNOWN_CLIENT
    assert resolve_client_address("10.0.0.5", None, trusted) != "10.0.0.5"

    # No edge known: peer used (matches the original comment about
    # failing closed to the peer when no edge is known).
    assert resolve_client_address("203.0.113.7", "198.51.100.10", ()) == "203.0.113.7"


TRUSTED_EDGE = ("10.0.0.5/32",)


def test_traefik_forwarded_client_public_ip_recorded() -> None:
    # Normal flow: client connects through Traefik (the trusted edge) and
    # Traefik appends the real client. Resolution returns the client, not the
    # edge address.
    assert resolve_client_address("10.0.0.5", "203.0.113.10", TRUSTED_EDGE) == "203.0.113.10"


def test_direct_backend_request_cannot_forge_forwarded_headers() -> None:
    # Direct connection to the panel backend (untrusted peer) carrying a forged
    # X-Forwarded-For header must resolve to the peer, never the victim IP.
    assert resolve_client_address("192.168.1.50", "203.0.113.66", TRUSTED_EDGE) == "192.168.1.50"


def test_untrusted_container_cannot_forge_another_client_ip() -> None:
    # A container on a shared Docker subnet is NOT the exact trusted edge
    # endpoint; it cannot pin a failure onto another client IP. This pins the
    # rule that WPFY never trusts an entire shared Docker subnet.
    assert resolve_client_address("172.20.0.12", "203.0.113.77", TRUSTED_EDGE) == "172.20.0.12"


def test_malformed_forwarded_chain_falls_back_safely() -> None:
    # Garbage entries are skipped; a later valid untrusted entry still wins.
    assert resolve_client_address(
        "10.0.0.5", "not-an-ip, 203.0.113.50, 10.0.0.5", TRUSTED_EDGE
    ) == "203.0.113.50"
    # A fully malformed chain resolves to the unknown sentinel, never the edge.
    assert resolve_client_address("10.0.0.5", "junk,,,", TRUSTED_EDGE) == _UNKNOWN_CLIENT
    assert resolve_client_address("10.0.0.5", "junk,,,", TRUSTED_EDGE) != "10.0.0.5"
    # An empty forwarded header also resolves to the unknown sentinel.
    assert resolve_client_address("10.0.0.5", "", TRUSTED_EDGE) == _UNKNOWN_CLIENT


def test_multiple_trusted_proxy_hops_resolve_correctly() -> None:
    trusted = ("10.0.0.5/32", "10.0.0.6/32")
    # Right-to-left walk skips every trusted hop, then returns the client.
    assert resolve_client_address(
        "10.0.0.6", "198.51.100.20, 10.0.0.5, 10.0.0.6", trusted
    ) == "198.51.100.20"
    # A chain made only of trusted hops cannot determine a client; never emit
    # the proxy's own IP.
    assert resolve_client_address("10.0.0.6", "10.0.0.5, 10.0.0.6", trusted) == _UNKNOWN_CLIENT
    assert resolve_client_address("10.0.0.6", "10.0.0.5, 10.0.0.6", trusted) != "10.0.0.6"


def test_ipv4_and_ipv6_normalization() -> None:
    # IPv6 trusted edge with an IPv6 client chain.
    assert resolve_client_address(
        "2001:db8::2", "2001:db8::1, 2001:db8::2", ("2001:db8::2/128",)
    ) == "2001:db8::1"
    # IPv6 peer cannot match an IPv4 trusted entry, so it cannot forge.
    assert resolve_client_address("2001:db8::2", "198.51.100.9", ("192.0.2.1/32",)) == "2001:db8::2"
    # IPv4 trusted edge with a genuine IPv6 client through it.
    assert resolve_client_address("10.0.0.5", "2001:db8::1", ("10.0.0.5/32",)) == "2001:db8::1"
    # Whitespace-padded IPv4 chain parses and resolves normally.
    assert resolve_client_address(
        "10.0.0.5", " 198.51.100.30 , 10.0.0.5 ", TRUSTED_EDGE
    ) == "198.51.100.30"


@pytest.fixture
def auth_log_home(tmp_path, monkeypatch):
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


def _read_auth_log(log_dir: str) -> list[dict]:
    import json

    path = Path(log_dir) / "panel-auth.log"
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def test_trusted_peer_without_forwarded_header_never_emits_edge_ip(auth_log_home) -> None:
    # End-to-end through the panel auth log: a trusted edge peer with NO
    # forwarded header must NOT emit a ban-triggering record keyed on the
    # proxy's own IP (never-ban set).
    import wpfy.panel_auth as panel_auth

    panel_auth.add_user("admin", "admin-password", role=panel_auth.ROLE_ADMIN)
    resolved = resolve_client_address("10.0.0.5", None, TRUSTED_EDGE)
    assert panel_auth.login("admin", "wrong", client=resolved) is None

    records = _read_auth_log(auth_log_home.log_dir)
    assert len(records) == 1
    assert records[0]["client_ip"] == _UNKNOWN_CLIENT
    assert records[0]["client_ip"] != "10.0.0.5"


# ---------------------------------------------------------------------------
# Phase 9: adversarial trusted-proxy scenarios (login-shield-plan.md 1017-1042)
# ---------------------------------------------------------------------------

# These tests are offline-only: they never shell out to Docker, and the only
# runtime-sensitive inputs (trusted discovery, Cloudflare ranges) are injected
# through env overrides or monkeypatched discovery.
@pytest.fixture(autouse=True)
def _offline_only(monkeypatch) -> None:
    monkeypatch.setenv("WPFY_SKIP_RUNTIME", "1")
    monkeypatch.delenv("WPFY_CLOUDFLARE_RANGES", raising=False)
    import wpfy.panel_auth as panel_auth

    # The emission guard discovers never-ban edge addresses from Docker on
    # first failure; keep every test offline and deterministic. Tests that
    # exercise the discovery path override this patch.
    monkeypatch.setattr(panel_auth, "_discover_never_ban_edge_cidrs", lambda: ())


def _address_in_cidrs(address: str, cidrs: tuple[str, ...]) -> bool:
    parsed = ipaddress.ip_address(address)
    return any(parsed in ipaddress.ip_network(raw, strict=False) for raw in cidrs)


def test_cloudflare_proxied_request_uses_real_client_when_cloudflare_configured(monkeypatch) -> None:
    # Scenario 8: when WPFY is configured for Cloudflare, Cloudflare edge
    # ranges join the trusted set (the site layer appends cloudflare_cidrs();
    # this is the same contract at the panel layer). A request that arrived
    # Traefik -> Cloudflare carries chain [real client, CF edge]; the walk
    # skips the CF edge and resolves the real client.
    monkeypatch.setenv("WPFY_CLOUDFLARE_RANGES", "172.64.0.0/13,2400:cb00::/32")
    import wpfy.cloudflare_ranges as cloudflare_ranges

    cf_trusted = tuple(cloudflare_ranges._effective_cidrs())
    trusted_with_cf = TRUSTED_EDGE + cf_trusted

    assert resolve_client_address(
        "10.0.0.5", "203.0.113.10, 172.64.0.10", trusted_with_cf
    ) == "203.0.113.10"
    # IPv6 Cloudflare edge is skipped the same way.
    assert resolve_client_address(
        "10.0.0.5", "2001:db8::10, 2400:cb00::1", trusted_with_cf
    ) == "2001:db8::10"
    # Without Cloudflare configured, the same chain resolves only to the CF
    # edge (walk stops at the first untrusted hop); the real client deeper in
    # the chain can never be forged past it.
    assert resolve_client_address(
        "10.0.0.5", "203.0.113.10, 172.64.0.10", TRUSTED_EDGE
    ) == "172.64.0.10"


def test_non_cloudflare_client_cannot_spoof_cf_connecting_ip() -> None:
    # Scenario 9: the panel resolves clients from the X-Forwarded-For chain
    # only; CF-Connecting-IP is never read, so there is no header to spoof.
    # An untrusted peer carrying a forged value resolves to the peer, never
    # the victim.
    assert resolve_client_address("198.51.100.10", "203.0.113.77", TRUSTED_EDGE) == "198.51.100.10"
    # From a trusted edge with Cloudflare NOT trusted, the walk stops at the
    # claimed CF edge and can never skip past it to a deeper victim.
    assert resolve_client_address("10.0.0.5", "203.0.113.77, 172.64.0.10", TRUSTED_EDGE) == "172.64.0.10"
    # A forged header value embedded in the chain is not a valid IP; it is
    # skipped and the chain still fails closed.
    assert resolve_client_address("10.0.0.5", "CF-Connecting-IP: 203.0.113.77", TRUSTED_EDGE) == _UNKNOWN_CLIENT
    assert resolve_client_address("10.0.0.5", "CF-Connecting-IP: 203.0.113.77", TRUSTED_EDGE) != "203.0.113.77"


def test_wpfy_never_bans_infrastructure_addresses(monkeypatch) -> None:
    # Scenario 10 (panel-layer contract): the trusted edge is never emitted as
    # a client; Docker bridge and unrelated-proxy peers cannot forge; Cloudflare
    # edge stops are within the known never-ban ranges; loopback is in the
    # fail2ban safe allowlist. (Full never-ban for bridge/CF/panel-backend is
    # enforced by the fail2ban allowlist layer in t03/t04; this pins what the
    # panel side already guarantees.)
    # 1. Traefik edge address: sentinel, never the proxy's own IP.
    for peer in ("10.0.0.5",):
        assert resolve_client_address(peer, None, TRUSTED_EDGE) == _UNKNOWN_CLIENT
        assert resolve_client_address(peer, None, TRUSTED_EDGE) != peer
    two_edge = ("10.0.0.5/32", "10.0.0.6/32")
    for peer in ("10.0.0.5", "10.0.0.6"):
        assert resolve_client_address(peer, None, two_edge) == _UNKNOWN_CLIENT
        assert resolve_client_address(peer, None, two_edge) != peer
    # 2. Docker bridge address: not a trusted edge (no shared-subnet trust),
    #    so it cannot forge another client, and it never enters the trusted set.
    assert resolve_client_address("172.17.0.2", "203.0.113.99", TRUSTED_EDGE) == "172.17.0.2"
    assert not _address_in_cidrs("172.17.0.2", TRUSTED_EDGE)
    # 3. Cloudflare edge addresses: known never-ban ranges; an unconfigured
    #    stop resolves to a CF edge inside the published ranges.
    monkeypatch.setenv("WPFY_CLOUDFLARE_RANGES", "172.64.0.0/13,2400:cb00::/32")
    import wpfy.cloudflare_ranges as cloudflare_ranges

    resolved_cf = resolve_client_address("10.0.0.5", "203.0.113.10, 172.64.0.10", TRUSTED_EDGE)
    assert resolved_cf == "172.64.0.10"
    assert cloudflare_ranges.is_cloudflare_ip(resolved_cf)
    # 4. Panel backend / loopback: loopback lives in the fail2ban safe allowlist.
    from wpfy.fail2ban_host import SAFE_ALLOWLIST

    assert _address_in_cidrs("127.0.0.1", SAFE_ALLOWLIST)
    assert _address_in_cidrs("::1", SAFE_ALLOWLIST)
    # 5. Unrelated proxy address: an untrusted peer records only itself and
    #    cannot pin a victim (never-ban for relays is the fail2ban allowlist's
    #    job in t03/t04).
    assert resolve_client_address("192.0.2.44", "203.0.113.10", TRUSTED_EDGE) == "192.0.2.44"


@pytest.mark.parametrize(
    "forwarded",
    (
        None,  # no X-Forwarded-For header at all
        "",  # empty header
        "junk,,,",  # fully malformed chain
        " , ",  # whitespace-only chain
        "10.0.0.5",  # chain of only the trusted edge hop
        "10.0.0.5, 10.0.0.5",  # chain of only the trusted edge hop, repeated
        "CF-Connecting-IP: 203.0.113.77",  # non-IP forged value
    ),
)
def test_fail_closed_indeterminate_client_never_records_proxy_identity(auth_log_home, forwarded) -> None:
    # Fail-closed (login-shield-plan.md 1039-1041): an indeterminate client
    # must resolve to the sentinel, never the trusted proxy IP, and the auth
    # log must not emit a ban-triggering record keyed on the proxy identity.
    import wpfy.panel_auth as panel_auth

    panel_auth.add_user("admin", "admin-password", role=panel_auth.ROLE_ADMIN)
    resolved = resolve_client_address("10.0.0.5", forwarded, TRUSTED_EDGE)
    assert resolved == _UNKNOWN_CLIENT
    assert resolved != "10.0.0.5"
    assert panel_auth.login("admin", "wrong", client=resolved) is None

    records = _read_auth_log(auth_log_home.log_dir)
    assert len(records) == 1
    assert records[0]["client_ip"] == _UNKNOWN_CLIENT
    assert records[0]["client_ip"] != "10.0.0.5"
    assert records[0]["event"] == "panel_auth_failure"
    assert records[0]["reason_class"] in {"invalid_credentials"}


def test_emission_guard_never_writes_bannable_never_ban_identity(auth_log_home, monkeypatch) -> None:
    # Gate scenario (t05a): never-ban must hold at resolution AND emission.
    # Resolution returns the 0.0.0.0 sentinel for a trusted peer with no
    # forwarded header; the emission guard redacts ANY never-ban identity that
    # reaches the writer (stale edge IP inside the TTL window, Docker bridge,
    # loopback, Cloudflare edge) and keeps the sentinel record for
    # observability (an iptables ban of 0.0.0.0 is a no-op).
    import wpfy.panel_auth as panel_auth

    monkeypatch.setattr(panel_auth, "_discover_never_ban_edge_cidrs", lambda: TRUSTED_EDGE)
    panel_auth.add_user("admin", "admin-password", role=panel_auth.ROLE_ADMIN)

    # Trusted peer, no forwarded header -> sentinel record, never the edge IP.
    resolved = resolve_client_address("10.0.0.5", None, TRUSTED_EDGE)
    assert resolved == _UNKNOWN_CLIENT
    assert panel_auth.login("admin", "wrong", client=resolved) is None

    # Emission guard: never-ban identities are redacted to the sentinel, and
    # the records are kept (observability) rather than dropped.
    for identity in ("10.0.0.5", "172.17.0.9", "127.0.0.1", "::1", "172.64.0.10"):
        assert panel_auth.login("admin", "wrong", client=identity) is None

    records = _read_auth_log(auth_log_home.log_dir)
    assert len(records) == 6
    assert [rec["client_ip"] for rec in records] == [_UNKNOWN_CLIENT] * 6
    assert all(rec["client_ip"] != "10.0.0.5" for rec in records)
    # Sentinel policy pinned by test: the 0.0.0.0 sentinel record is kept.
    assert records[0]["client_ip"] == _UNKNOWN_CLIENT


def test_legitimate_attacker_behind_trusted_proxy_still_emits_real_ip(auth_log_home, monkeypatch) -> None:
    # Never over-drop (t05a): a genuine attacker IP from a valid forwarded
    # chain is not in the never-ban set and must still be emitted so the
    # fail2ban layer can act. The emission guard must not redact it.
    import wpfy.panel_auth as panel_auth

    monkeypatch.setattr(panel_auth, "_discover_never_ban_edge_cidrs", lambda: TRUSTED_EDGE)
    panel_auth.add_user("admin", "admin-password", role=panel_auth.ROLE_ADMIN)

    resolved = resolve_client_address("10.0.0.5", "203.0.113.77", TRUSTED_EDGE)
    assert resolved == "203.0.113.77"
    assert panel_auth.login("admin", "wrong", client=resolved) is None

    records = _read_auth_log(auth_log_home.log_dir)
    assert len(records) == 1
    assert records[0]["client_ip"] == "203.0.113.77"
