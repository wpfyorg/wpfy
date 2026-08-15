"""Self-signed TLS for the domainless panel.

`wpfy panel expose <domain>` puts the panel behind Traefik with a real ACME
certificate. Not every operator has a domain, so exposure without one binds the
panel directly on a public address instead -- and a public address cannot have a
Let's Encrypt certificate, because no CA issues for a bare IP.

Plaintext is not an option there. First-run account creation sends a password
and, during enrolment, a TOTP secret; a session afterwards carries a bearer
token on every request. On the open internet all three are readable by anyone on
the path.

So that mode gets a self-signed certificate. The browser will warn -- there is no
chain to a trusted root and cannot be one -- and a warning an operator clicks
through blindly is worth very little. The command therefore prints the
certificate's SHA-256 fingerprint next to the URL, so the warning can be checked
against the host that actually generated the key rather than accepted on faith.

Generation shells out to `openssl`, which is already required elsewhere in wpfy
(`site_security` uses it for password hashing) and keeps this module free of a
runtime dependency. The private key is written 0600 and never leaves the host.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
import hashlib
import ipaddress
import os
from pathlib import Path
import re
import shutil
import subprocess

from . import settings

#: Public CAs stopped honouring longer lifetimes years ago and browsers cap what
#: they accept. 825 days is the conventional ceiling and is well past the point
#: where an operator should have moved to a real domain.
CERTIFICATE_DAYS = 825
_KEY_BITS = 2048
_PEM_BODY = re.compile(
    r"-----BEGIN CERTIFICATE-----(?P<body>.*?)-----END CERTIFICATE-----", re.DOTALL
)


@dataclass(frozen=True, slots=True)
class SelfSignedCertificate:
    certificate_path: Path
    key_path: Path
    fingerprint: str
    generated: bool


def tls_dir() -> Path:
    return Path(settings.PATHS.config_dir) / "panel-tls"


def certificate_path() -> Path:
    return tls_dir() / "panel-self-signed.crt"


def key_path() -> Path:
    return tls_dir() / "panel-self-signed.key"


def openssl_available() -> bool:
    return shutil.which("openssl") is not None


def fingerprint_of(certificate: str | Path) -> str:
    """SHA-256 over the DER body, formatted the way browsers show it.

    Hashing here rather than shelling out to `openssl x509 -fingerprint` keeps
    the value derived from the bytes actually on disk -- the same bytes the
    server will present -- instead of from a second process's reading of them.
    """
    text = Path(certificate).read_text(encoding="utf-8") if isinstance(certificate, Path) else certificate
    match = _PEM_BODY.search(text)
    if not match:
        raise ValueError("not a PEM certificate")
    der = base64.b64decode("".join(match.group("body").split()))
    digest = hashlib.sha256(der).hexdigest().upper()
    return ":".join(digest[index:index + 2] for index in range(0, len(digest), 2))


def _subject_alt_name(host: str) -> str:
    """A bare IP has to appear as an IP SAN; a CN alone is ignored by browsers."""
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return f"DNS:{host}"
    return f"IP:{host}"


def ensure_self_signed(host: str, *, force: bool = False) -> SelfSignedCertificate:
    """Return the panel's self-signed certificate, generating it if needed.

    Regenerating on every start would change the fingerprint the operator was
    told to check, which would train them to ignore it. The existing pair is
    reused unless it is missing, unreadable, or `force` is set.
    """
    if not isinstance(host, str) or not host.strip():
        raise ValueError("a host is required to generate a certificate")
    host = host.strip()
    certificate, key = certificate_path(), key_path()

    if not force and certificate.exists() and key.exists():
        try:
            return SelfSignedCertificate(certificate, key, fingerprint_of(certificate), generated=False)
        except (OSError, ValueError):
            pass  # unreadable or not a certificate; fall through and replace it

    if not openssl_available():
        raise RuntimeError(
            "openssl is required to generate the panel certificate; install it or "
            "expose the panel with a domain instead"
        )

    directory = tls_dir()
    directory.mkdir(parents=True, exist_ok=True)
    os.chmod(directory, 0o700)

    completed = subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", f"rsa:{_KEY_BITS}", "-nodes",
            "-keyout", str(key), "-out", str(certificate),
            "-days", str(CERTIFICATE_DAYS), "-subj", f"/CN={host}",
            "-addext", f"subjectAltName={_subject_alt_name(host)}",
        ],
        check=False, capture_output=True, text=True, timeout=120,
    )
    if completed.returncode != 0:
        raise RuntimeError(
            f"could not generate the panel certificate: {(completed.stderr or '').strip() or 'openssl failed'}"
        )

    # The key authenticates the panel to every browser that trusts the printed
    # fingerprint. It never needs to be readable by anyone but root.
    os.chmod(key, 0o600)
    os.chmod(certificate, 0o644)
    return SelfSignedCertificate(certificate, key, fingerprint_of(certificate), generated=True)


def ssl_context(certificate: SelfSignedCertificate):
    """A TLS context for the panel's own socket.

    Imported lazily so a host without the `ssl` module -- a stripped Python
    build -- fails when TLS is actually asked for, with a clear reason, rather
    than at import time for every wpfy command.
    """
    import ssl

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(str(certificate.certificate_path), str(certificate.key_path))
    return context
