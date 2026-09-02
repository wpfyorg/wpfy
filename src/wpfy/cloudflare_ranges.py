"""Cloudflare IP range detection and validation."""
from __future__ import annotations

import ipaddress
import os
from functools import lru_cache

# Cloudflare's published edge IP ranges.
# Source: https://www.cloudflare.com/ips-v4 and https://www.cloudflare.com/ips-v6
# Fetched: 2026-06-05. These change rarely; refresh from the URLs above if a
# Cloudflare-fronted domain stops being detected as proxied.
CLOUDFLARE_IPV4 = (
    "173.245.48.0/20",
    "103.21.244.0/22",
    "103.22.200.0/22",
    "103.31.4.0/22",
    "141.101.64.0/18",
    "108.162.192.0/18",
    "190.93.240.0/20",
    "188.114.96.0/20",
    "197.234.240.0/22",
    "198.41.128.0/17",
    "162.158.0.0/15",
    "104.16.0.0/13",
    "104.24.0.0/14",
    "172.64.0.0/13",
    "131.0.72.0/22",
)

CLOUDFLARE_IPV6 = (
    "2400:cb00::/32",
    "2606:4700::/32",
    "2803:f800::/32",
    "2405:b500::/32",
    "2405:8100::/32",
    "2a06:98c0::/29",
    "2c0f:f248::/32",
)


def _effective_cidrs() -> tuple[str, ...]:
    override = os.environ.get("WPFY_CLOUDFLARE_RANGES")
    if override:
        return tuple(raw.strip() for raw in override.split(",") if raw.strip())
    return CLOUDFLARE_IPV4 + CLOUDFLARE_IPV6


@lru_cache(maxsize=None)
def _networks(cidrs: tuple[str, ...]) -> tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]:
    nets: list[ipaddress._BaseNetwork] = []
    for cidr in cidrs:
        try:
            nets.append(ipaddress.ip_network(cidr, strict=False))
        except ValueError:
            continue
    return tuple(nets)


def is_cloudflare_ip(ip: str) -> bool:
    """Check if cloudflare ip."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for net in _networks(_effective_cidrs()):
        if addr.version == net.version and addr in net:
            return True
    return False


def ips_are_cloudflare(ips: tuple[str, ...] | list[str]) -> bool:
    """True when the set is non-empty and every IP belongs to Cloudflare.

    A partial match (some Cloudflare, some not) is treated as not proxied so we
    do not silently skip the VPS IP check on a misconfigured domain.
    """
    if not ips:
        return False
    return all(is_cloudflare_ip(ip) for ip in ips)
