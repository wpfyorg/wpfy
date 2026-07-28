from __future__ import annotations

import base64
import datetime
import json
from dataclasses import dataclass
import ipaddress
import os
import subprocess
import socket
import tempfile
from urllib.request import urlopen

from .cloudflare_ranges import ips_are_cloudflare
from .site_runtime import RuntimeResult, docker_available, runtime_skip_requested
from .traefik import TRAEFIK_CONTAINER


def _current_paths():
    from .settings import PATHS as current_paths

    return current_paths


@dataclass(frozen=True)
class SSLPreflightResult:
    domain: str
    a_records: tuple[str, ...]
    aaaa_records: tuple[str, ...]
    public_ipv4: tuple[str, ...]
    public_ipv6: tuple[str, ...]
    passed: bool
    message: str
    mode: str = "direct"


def resolve_domain_ips(domain: str) -> tuple[tuple[str, ...], tuple[str, ...]]:
    override = os.environ.get("WPFY_TEST_DNS_IPS")
    if override:
        ipv4: set[str] = set()
        ipv6: set[str] = set()
        for raw in override.split(","):
            raw = raw.strip()
            if not raw:
                continue
            parsed = ipaddress.ip_address(raw)
            if parsed.version == 4:
                ipv4.add(str(parsed))
            else:
                ipv6.add(str(parsed))
        return tuple(sorted(ipv4)), tuple(sorted(ipv6))

    a_records: set[str] = set()
    aaaa_records: set[str] = set()
    try:
        infos = socket.getaddrinfo(domain, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except socket.gaierror:
        return (), ()

    for info in infos:
        address = info[4][0]
        try:
            parsed = ipaddress.ip_address(address)
        except ValueError:
            continue
        if parsed.version == 4:
            a_records.add(str(parsed))
        else:
            aaaa_records.add(str(parsed))
    return tuple(sorted(a_records)), tuple(sorted(aaaa_records))


def public_ip_via_url(url: str) -> str | None:
    try:
        with urlopen(url, timeout=3) as response:
            text = response.read().decode("utf-8").strip()
    except Exception:
        return None
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return None


def detect_public_ips() -> tuple[tuple[str, ...], tuple[str, ...]]:
    override = os.environ.get("WPFY_TEST_PUBLIC_IPS")
    if override:
        ipv4: set[str] = set()
        ipv6: set[str] = set()
        for raw in override.split(","):
            raw = raw.strip()
            if not raw:
                continue
            parsed = ipaddress.ip_address(raw)
            if parsed.version == 4:
                ipv4.add(str(parsed))
            else:
                ipv6.add(str(parsed))
        return tuple(sorted(ipv4)), tuple(sorted(ipv6))

    ipv4: set[str] = set()
    ipv6: set[str] = set()

    for url in (
        "https://api.ipify.org",
        "https://ifconfig.me/ip",
        "https://checkip.amazonaws.com",
    ):
        value = public_ip_via_url(url)
        if not value:
            continue
        parsed = ipaddress.ip_address(value)
        if parsed.version == 4:
            ipv4.add(str(parsed))
            break
        else:
            ipv6.add(str(parsed))

    return tuple(sorted(ipv4)), tuple(sorted(ipv6))


def preflight_ssl(domain: str) -> SSLPreflightResult:
    a_records, aaaa_records = resolve_domain_ips(domain)
    public_ipv4, public_ipv6 = detect_public_ips()

    matched_v4 = set(a_records).intersection(public_ipv4)
    matched_v6 = set(aaaa_records).intersection(public_ipv6)
    resolved = a_records + aaaa_records
    records_summary = (
        f"A={','.join(a_records) or 'none'}; "
        f"AAAA={','.join(aaaa_records) or 'none'}; "
        f"public_ipv4={','.join(public_ipv4) or 'unknown'}; "
        f"public_ipv6={','.join(public_ipv6) or 'unknown'}"
    )

    if matched_v4 or matched_v6:
        passed = True
        mode = "direct"
        message = f"DNS/IP preflight passed for {domain}; {records_summary}"
    elif ips_are_cloudflare(resolved):
        passed = True
        mode = "proxied"
        message = (
            f"proxied domain (Cloudflare) detected for {domain}; "
            f"issuing via HTTP-01; {records_summary}"
        )
    else:
        passed = False
        mode = "direct"
        message = f"DNS/IP preflight failed for {domain}; {records_summary}"

    return SSLPreflightResult(
        domain=domain,
        a_records=a_records,
        aaaa_records=aaaa_records,
        public_ipv4=public_ipv4,
        public_ipv6=public_ipv6,
        passed=passed,
        message=message,
        mode=mode,
    )


def _acme_json_path() -> str:
    return os.path.join(_current_paths().traefik_dir, "letsencrypt", "acme.json")


def _read_acme_file() -> list[dict] | None:
    path = _acme_json_path()
    data: dict | None = None
    if os.path.exists(path):
        try:
            with open(path, encoding="utf-8") as fh:
                loaded = json.load(fh)
            if isinstance(loaded, dict):
                data = loaded
        except (OSError, json.JSONDecodeError):
            return None
    else:
        try:
            proc = subprocess.run(
                ["docker", "exec", "wpfy-traefik", "cat", "/letsencrypt/acme.json"],
                check=False,
                capture_output=True,
                text=True,
            )
        except FileNotFoundError:
            return None
        if proc.returncode != 0:
            return None
        try:
            loaded = json.loads(proc.stdout)
            if isinstance(loaded, dict):
                data = loaded
        except json.JSONDecodeError:
            return None

    if data is None:
        return None
    merged: list[dict] = []
    found = False
    for resolver in data.values():
        if not isinstance(resolver, dict):
            continue
        certs = resolver.get("Certificates")
        if isinstance(certs, list):
            merged.extend(certs)
            found = True
    if not found:
        return None
    return merged


def _parse_cert_data(cert_entry: dict) -> dict | None:
    cert_b64 = cert_entry.get("certificate", "")
    if not cert_b64:
        return None
    try:
        cert_bytes = base64.b64decode(cert_b64)
    except Exception:
        return None
    # Traefik stores certs as base64-encoded PEM (not DER); detect by header.
    is_pem = cert_bytes.lstrip().startswith(b"-----BEGIN")
    return _parse_cert_data_with_openssl(cert_bytes, is_pem=is_pem)


def _parse_cert_data_with_openssl(cert_bytes: bytes, *, is_pem: bool = False) -> dict | None:
    inform = "PEM" if is_pem else "DER"
    with tempfile.NamedTemporaryFile() as cert_file:
        cert_file.write(cert_bytes)
        cert_file.flush()
        try:
            proc = subprocess.run(
                [
                    "openssl", "x509", f"-inform", inform, "-in", cert_file.name,
                    "-noout", "-issuer", "-dates", "-ext", "subjectAltName",
                ],
                check=False,
                capture_output=True,
                text=True,
            )
        except FileNotFoundError:
            return None
    if proc.returncode != 0:
        return None

    issuer = ""
    not_before = ""
    not_after = ""
    sans: list[str] = []
    for line in proc.stdout.splitlines():
        stripped = line.strip()
        if stripped.startswith("issuer="):
            issuer = stripped.removeprefix("issuer=")
        elif stripped.startswith("notBefore="):
            not_before = stripped.removeprefix("notBefore=")
        elif stripped.startswith("notAfter="):
            not_after = stripped.removeprefix("notAfter=")
        elif stripped.startswith("DNS:"):
            sans.extend(
                part.strip().removeprefix("DNS:").strip()
                for part in stripped.split(",")
                if part.strip().startswith("DNS:")
            )
    return {
        "issuer": issuer,
        "not_before": not_before,
        "not_after": not_after,
        "sans": sans,
    }


def _parse_not_after(value: str) -> datetime.datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=datetime.timezone.utc)
        return parsed
    except ValueError:
        pass
    try:
        parsed = datetime.datetime.strptime(value, "%b %d %H:%M:%S %Y %Z")
        return parsed.replace(tzinfo=datetime.timezone.utc)
    except ValueError:
        return None


def get_cert_info(domain: str) -> dict:
    certs = _read_acme_file()
    expected_domain = domain.rstrip(".").lower()
    if certs is None:
        return {"status": "unavailable", "issuer": "", "not_before": "", "not_after": "", "sans": []}
    if not certs:
        return {"status": "empty", "issuer": "", "not_before": "", "not_after": "", "sans": []}
    for cert_entry in certs:
        domains = cert_entry.get("domain", {})
        if not isinstance(domains, dict):
            continue
        main = domains.get("main", "")
        sans = domains.get("sans", [])
        main_key = str(main).rstrip(".").lower()
        san_keys = {str(san).rstrip(".").lower() for san in sans}
        if expected_domain == main_key or expected_domain in san_keys:
            parsed = _parse_cert_data(cert_entry)
            if parsed:
                return {
                    "status": "issued",
                    "issuer": parsed["issuer"],
                    "not_before": parsed["not_before"],
                    "not_after": parsed["not_after"],
                    "sans": parsed["sans"],
                }
            else:
                return {
                    "status": "issued",
                    "issuer": "",
                    "not_before": "",
                    "not_after": "",
                    "sans": [],
                }
    return {"status": "not_found", "issuer": "", "not_before": "", "not_after": "", "sans": []}


def list_certificates() -> list[dict]:
    certs = _read_acme_file()
    if certs is None or not certs:
        return []
    results: list[dict] = []
    for cert_entry in certs:
        domains = cert_entry.get("domain", {})
        if not isinstance(domains, dict):
            continue
        main = domains.get("main", "")
        sans = domains.get("sans", [])
        all_domains = [main] + list(sans) if main else list(sans)
        parsed = _parse_cert_data(cert_entry)
        for d in all_domains:
            results.append({
                "domain": d,
                "status": "issued",
                "issuer": parsed["issuer"] if parsed else "",
                "not_before": parsed["not_before"] if parsed else "",
                "not_after": parsed["not_after"] if parsed else "",
                "sans": [s for s in all_domains if s != d] if parsed else [],
            })
    return results


def cert_expiry_days(domain: str) -> int | None:
    cert_info = get_cert_info(domain)
    if cert_info.get("status") != "issued":
        return None
    not_after = _parse_not_after(cert_info.get("not_after", ""))
    if not_after is None:
        return None
    now = datetime.datetime.now(datetime.timezone.utc)
    delta = not_after.astimezone(datetime.timezone.utc) - now
    return delta.days


def force_renew_cert(domain: str) -> RuntimeResult:
    if runtime_skip_requested():
        return RuntimeResult(0, f"certificate renewal for {domain} skipped by WPFY_SKIP_RUNTIME=1", skipped=True)
    if not docker_available():
        return RuntimeResult(0, f"certificate renewal for {domain} skipped (Docker/Compose not available)", skipped=True)

    cert_info = get_cert_info(domain)
    if cert_info["status"] == "unavailable":
        return RuntimeResult(1, "could not read acme.json from traefik container")
    if cert_info["status"] in ("empty", "not_found"):
        return RuntimeResult(0, f"no existing certificate for {domain}; it will be issued by Traefik on next request")

    proc = subprocess.run(
        ["docker", "exec", TRAEFIK_CONTAINER, "mkdir", "-p", "/tmp/acme-backup"],
        check=False,
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        message = proc.stderr.strip() or proc.stdout.strip() or "backup directory creation failed"
        return RuntimeResult(proc.returncode or 1, f"could not prepare ACME backup: {message}")
    proc = subprocess.run(
        ["docker", "exec", TRAEFIK_CONTAINER, "cp", "/letsencrypt/acme.json", "/tmp/acme-backup/acme.json"],
        check=False,
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        message = proc.stderr.strip() or proc.stdout.strip() or "backup copy failed"
        return RuntimeResult(proc.returncode or 1, f"could not back up acme.json: {message}")
    read_proc = subprocess.run(
        ["docker", "exec", TRAEFIK_CONTAINER, "cat", "/letsencrypt/acme.json"],
        check=False,
        capture_output=True,
        text=True,
    )
    if read_proc.returncode != 0:
        message = read_proc.stderr.strip() or read_proc.stdout.strip() or "read failed"
        return RuntimeResult(
            read_proc.returncode or 1,
            f"could not read acme.json: {message}; backup preserved but renewal cannot proceed",
        )
    try:
        full_data = json.loads(read_proc.stdout)
    except json.JSONDecodeError:
        return RuntimeResult(1, "could not read acme.json; backup preserved but renewal cannot proceed")
    if not isinstance(full_data, dict):
        return RuntimeResult(1, "unexpected acme.json format; backup preserved but renewal cannot proceed")

    expected_domain = domain.rstrip(".").lower()
    removed = False
    for resolver in full_data.values():
        if not isinstance(resolver, dict):
            continue
        certs = resolver.get("Certificates")
        if not isinstance(certs, list):
            continue
        kept = []
        for cert_entry in certs:
            domains = cert_entry.get("domain", {})
            main = domains.get("main", "") if isinstance(domains, dict) else ""
            sans = domains.get("sans", []) if isinstance(domains, dict) else []
            keys = {str(main).rstrip(".").lower(), *(str(san).rstrip(".").lower() for san in sans)}
            if expected_domain in keys:
                removed = True
            else:
                kept.append(cert_entry)
        resolver["Certificates"] = kept

    if not removed:
        return RuntimeResult(0, f"no certificate to remove for {domain}")

    proc = subprocess.run(
        ["docker", "exec", "-i", TRAEFIK_CONTAINER, "sh", "-c", "cat > /letsencrypt/acme.json"],
        check=False,
        capture_output=True,
        text=True,
        input=json.dumps(full_data, indent=2),
    )
    if proc.returncode != 0:
        message = proc.stderr.strip() or "unknown error"
        return RuntimeResult(1, f"failed to update acme.json: {message}; ACME was not replaced; backup preserved")

    proc = subprocess.run(
        ["docker", "kill", "-s", "HUP", TRAEFIK_CONTAINER],
        check=False,
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        message = proc.stderr.strip() or proc.stdout.strip() or "traefik reload failed"
        return RuntimeResult(
            proc.returncode,
            f"acme.json updated but Traefik reload failed: {message}; backup preserved",
            ran=True,
        )
    return RuntimeResult(
        0,
        f"certificate for {domain} removed from acme.json; Traefik will re-issue on next request",
        ran=True,
    )
