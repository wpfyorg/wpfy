from __future__ import annotations

from wpfy.cloudflare_ranges import is_cloudflare_ip, ips_are_cloudflare


def test_is_cloudflare_ip_true_for_known_cf_v4():
    assert is_cloudflare_ip("104.16.0.1") is True


def test_is_cloudflare_ip_true_for_known_cf_v6():
    assert is_cloudflare_ip("2606:4700::1") is True


def test_is_cloudflare_ip_false_for_vps_ip():
    assert is_cloudflare_ip("1.2.3.4") is False


def test_is_cloudflare_ip_false_for_garbage():
    assert is_cloudflare_ip("not-an-ip") is False


def test_ips_are_cloudflare_all_match():
    assert ips_are_cloudflare(("104.16.0.1", "172.64.0.5")) is True


def test_ips_are_cloudflare_empty_is_false():
    assert ips_are_cloudflare(()) is False


def test_ips_are_cloudflare_partial_is_false():
    assert ips_are_cloudflare(("104.16.0.1", "1.2.3.4")) is False


def test_env_override_replaces_ranges(monkeypatch):
    monkeypatch.setenv("WPFY_CLOUDFLARE_RANGES", "10.0.0.0/8")
    assert is_cloudflare_ip("10.1.2.3") is True
    # Real Cloudflare IP no longer matches once the table is overridden.
    assert is_cloudflare_ip("104.16.0.1") is False


def test_effective_ranges_parse_once_and_follow_override_changes(monkeypatch):
    import wpfy.cloudflare_ranges as ranges

    calls = []
    real_parser = ranges.ipaddress.ip_network
    monkeypatch.setattr(
        ranges.ipaddress,
        "ip_network",
        lambda cidr, **kwargs: calls.append(cidr) or real_parser(cidr, **kwargs),
    )
    monkeypatch.setenv("WPFY_CLOUDFLARE_RANGES", "10.0.0.0/8,invalid")

    assert ranges.is_cloudflare_ip("10.1.2.3") is True
    assert ranges.is_cloudflare_ip("10.2.3.4") is True
    assert calls == ["10.0.0.0/8", "invalid"]

    monkeypatch.setenv("WPFY_CLOUDFLARE_RANGES", "192.0.2.0/24")
    assert ranges.is_cloudflare_ip("10.1.2.3") is False
    assert ranges.is_cloudflare_ip("192.0.2.1") is True
    assert calls == ["10.0.0.0/8", "invalid", "192.0.2.0/24"]
