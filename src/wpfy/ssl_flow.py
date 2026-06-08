"""Compatibility imports for the certificate lifecycle module."""

from .certificate_lifecycle import (
    SSLPreflightResult,
    cert_expiry_days,
    detect_public_ips,
    get_cert_info,
    list_certificates,
    preflight_ssl,
    public_ip_via_url,
    resolve_domain_ips,
)

__all__ = [
    "SSLPreflightResult",
    "cert_expiry_days",
    "detect_public_ips",
    "get_cert_info",
    "list_certificates",
    "preflight_ssl",
    "public_ip_via_url",
    "resolve_domain_ips",
]
