"""DNS provider configuration and validation."""
from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
from urllib.error import URLError
from urllib.request import Request, urlopen

from .redaction import redact_values
from .settings import current_paths
from .site_paths import read_env


@dataclass(frozen=True, slots=True)
class CloudflareConfig:
    """Cloudflare DNS provider configuration."""
    token: str


class DNSConfigError(RuntimeError):
    """DNS configuration error."""
    pass


def cloudflare_config_path() -> Path:
    """Return cloudflare config path."""
    return Path(current_paths().config_dir) / "dns-cloudflare.env"


def write_cloudflare_config(config: CloudflareConfig) -> Path:
    """Write cloudflare config."""
    path = cloudflare_config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w", encoding="utf-8") as output:
        os.fchmod(output.fileno(), 0o600)
        output.write(f"CF_DNS_API_TOKEN={config.token}\n")
    path.chmod(0o600)
    return path


def load_cloudflare_config() -> CloudflareConfig:
    """Load cloudflare config."""
    path = cloudflare_config_path()
    try:
        values = {key: value.strip() for key, value in read_env(path).items()}
    except OSError as exc:
        raise DNSConfigError(f"cannot read Cloudflare DNS config: {exc}") from exc
    if not values and not path.exists():
        raise DNSConfigError("Cloudflare DNS is not configured; run `wpfy dns cloudflare set --token-stdin`")
    token = values.get("CF_DNS_API_TOKEN", "")
    if not token:
        raise DNSConfigError("Cloudflare DNS token is missing")
    return CloudflareConfig(token=token)


def clear_cloudflare_config() -> None:
    """Clear cloudflare config."""
    path = cloudflare_config_path()
    if path.exists():
        path.unlink()


def test_cloudflare_config(config: CloudflareConfig) -> str:
    """Get test cloudflare configuration."""
    request = Request(
        "https://api.cloudflare.com/client/v4/user/tokens/verify",
        headers={"Authorization": f"Bearer {config.token}", "Accept": "application/json"},
        method="GET",
    )
    try:
        with urlopen(request, timeout=15) as response:
            status = getattr(response, "status", 200)
    except URLError as exc:
        raise OSError(str(exc.reason)) from exc
    if status >= 400:
        raise OSError(f"status {status}")
    return "Cloudflare token verified"


def redact_cloudflare_secret(message: str, config: CloudflareConfig) -> str:
    """Redact cloudflare secret."""
    return redact_values(message, (config.token,))
