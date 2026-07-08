from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import hmac
import os
from pathlib import Path
from typing import Final, Protocol
from urllib.error import URLError
from urllib.parse import quote, urlparse, urlunparse
from urllib.request import Request, urlopen

from .settings import PATHS


SERVICE: Final = "s3"
ALGORITHM: Final = "AWS4-HMAC-SHA256"
CONFIG_FILENAME: Final = "backup-storage.env"
REQUIRED_ENV: Final = (
    "WPFY_BACKUP_S3_ENDPOINT",
    "WPFY_BACKUP_S3_BUCKET",
    "WPFY_BACKUP_S3_REGION",
    "WPFY_BACKUP_S3_ACCESS_KEY",
    "WPFY_BACKUP_S3_SECRET_KEY",
)


@dataclass(frozen=True, slots=True)
class S3Config:
    endpoint: str
    bucket: str
    region: str
    prefix: str
    access_key: str
    secret_key: str


class S3ConfigError(RuntimeError):
    pass


class Opener(Protocol):
    def __call__(self, request: Request, *, timeout: int) -> object:
        pass


class S3Uploader:
    def __init__(self, opener: Opener = urlopen) -> None:
        self._opener = opener

    def upload_archive(self, config: S3Config, archive_path: Path, domain: str) -> str:
        payload = archive_path.read_bytes()
        key = s3_object_key(config.prefix, domain, archive_path.name)
        return self.upload_bytes(config, key, payload)

    def upload_bytes(self, config: S3Config, key: str, payload: bytes) -> str:
        request = signed_put_request(config, key, payload)
        try:
            with self._opener(request, timeout=60) as response:
                status = getattr(response, "status", 200)
        except URLError as exc:
            raise OSError(str(exc.reason)) from exc
        if status >= 400:
            raise OSError(f"status {status}")
        return f"s3://{config.bucket}/{key}"


def s3_config_path() -> Path:
    return Path(PATHS.config_dir) / CONFIG_FILENAME


def write_s3_config(config: S3Config) -> Path:
    path = s3_config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "\n".join([
            f"WPFY_BACKUP_S3_ENDPOINT={_normalized_endpoint(config.endpoint)}",
            f"WPFY_BACKUP_S3_BUCKET={config.bucket}",
            f"WPFY_BACKUP_S3_REGION={config.region}",
            f"WPFY_BACKUP_S3_PREFIX={config.prefix.strip('/')}",
            f"WPFY_BACKUP_S3_ACCESS_KEY={config.access_key}",
            f"WPFY_BACKUP_S3_SECRET_KEY={config.secret_key}",
            "",
        ]),
        encoding="utf-8",
    )
    path.chmod(0o600)
    return path


def clear_s3_config() -> None:
    path = s3_config_path()
    if path.exists():
        path.unlink()


def load_s3_config() -> S3Config:
    env_config = _load_env_config()
    if env_config is not None:
        return env_config
    stored_config = _load_stored_config()
    if stored_config is not None:
        return stored_config
    raise S3ConfigError("backup storage is not configured; run `wpfy backup storage set`")


def _load_env_config() -> S3Config | None:
    values = {
        "WPFY_BACKUP_S3_ENDPOINT": os.environ.get("WPFY_BACKUP_S3_ENDPOINT", "").strip(),
        "WPFY_BACKUP_S3_BUCKET": os.environ.get("WPFY_BACKUP_S3_BUCKET", "").strip(),
        "WPFY_BACKUP_S3_REGION": os.environ.get("WPFY_BACKUP_S3_REGION", "").strip(),
        "WPFY_BACKUP_S3_ACCESS_KEY": os.environ.get("WPFY_BACKUP_S3_ACCESS_KEY", "").strip(),
        "WPFY_BACKUP_S3_SECRET_KEY": os.environ.get("WPFY_BACKUP_S3_SECRET_KEY", "").strip(),
    }
    if not any(values.values()) and not os.environ.get("WPFY_BACKUP_S3_PREFIX", "").strip():
        return None
    missing = [key for key, value in values.items() if not value]
    if missing:
        raise S3ConfigError(f"missing {', '.join(missing)}")
    return S3Config(
        endpoint=_normalized_endpoint(values["WPFY_BACKUP_S3_ENDPOINT"]),
        bucket=values["WPFY_BACKUP_S3_BUCKET"],
        region=values["WPFY_BACKUP_S3_REGION"],
        prefix=os.environ.get("WPFY_BACKUP_S3_PREFIX", "").strip("/"),
        access_key=values["WPFY_BACKUP_S3_ACCESS_KEY"],
        secret_key=values["WPFY_BACKUP_S3_SECRET_KEY"],
    )


def _load_stored_config() -> S3Config | None:
    path = s3_config_path()
    if not path.exists():
        return None
    values: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key] = value.strip()
    missing = [key for key in REQUIRED_ENV if not values.get(key)]
    if missing:
        raise S3ConfigError(f"missing {', '.join(missing)}")
    return S3Config(
        endpoint=_normalized_endpoint(values["WPFY_BACKUP_S3_ENDPOINT"]),
        bucket=values["WPFY_BACKUP_S3_BUCKET"],
        region=values["WPFY_BACKUP_S3_REGION"],
        prefix=values.get("WPFY_BACKUP_S3_PREFIX", "").strip("/"),
        access_key=values["WPFY_BACKUP_S3_ACCESS_KEY"],
        secret_key=values["WPFY_BACKUP_S3_SECRET_KEY"],
    )


def _normalized_endpoint(endpoint: str) -> str:
    normalized = endpoint.strip()
    if "://" not in normalized:
        normalized = f"https://{normalized}"
    return normalized.rstrip("/")


def s3_object_key(prefix: str, domain: str, archive_name: str) -> str:
    parts = [part for part in (prefix.strip("/"), domain, archive_name) if part]
    return "/".join(parts)


def redact_s3_secrets(message: str, config: S3Config) -> str:
    redacted = message
    for secret in (config.access_key, config.secret_key):
        if secret:
            redacted = redacted.replace(secret, "***REDACTED***")
    return redacted


def signed_put_request(config: S3Config, key: str, payload: bytes) -> Request:
    parsed = urlparse(config.endpoint)
    if not parsed.scheme or not parsed.netloc:
        raise S3ConfigError("invalid WPFY_BACKUP_S3_ENDPOINT")
    now = datetime.now(timezone.utc)
    date_stamp = now.strftime("%Y%m%d")
    amz_date = now.strftime("%Y%m%dT%H%M%SZ")
    encoded_bucket = quote(config.bucket, safe="")
    encoded_key = quote(key, safe="/")
    canonical_uri = f"{parsed.path.rstrip('/')}/{encoded_bucket}/{encoded_key}"
    payload_hash = hashlib.sha256(payload).hexdigest()
    host = parsed.netloc
    headers = {
        "Host": host,
        "x-amz-content-sha256": payload_hash,
        "x-amz-date": amz_date,
    }
    signed_headers = "host;x-amz-content-sha256;x-amz-date"
    canonical_headers = "\n".join(f"{name.lower()}:{headers[name]}" for name in sorted(headers)) + "\n"
    canonical_request = "\n".join([
        "PUT",
        canonical_uri,
        "",
        canonical_headers,
        signed_headers,
        payload_hash,
    ])
    credential_scope = f"{date_stamp}/{config.region}/{SERVICE}/aws4_request"
    string_to_sign = "\n".join([
        ALGORITHM,
        amz_date,
        credential_scope,
        hashlib.sha256(canonical_request.encode("utf-8")).hexdigest(),
    ])
    signature = hmac.new(
        signing_key(config.secret_key, date_stamp, config.region),
        string_to_sign.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    headers["Authorization"] = (
        f"{ALGORITHM} Credential={config.access_key}/{credential_scope}, "
        f"SignedHeaders={signed_headers}, Signature={signature}"
    )
    url = urlunparse((parsed.scheme, parsed.netloc, canonical_uri, "", "", ""))
    return Request(url, data=payload, headers=headers, method="PUT")


def signing_key(secret_key: str, date_stamp: str, region: str) -> bytes:
    date_key = hmac.new(f"AWS4{secret_key}".encode("utf-8"), date_stamp.encode("utf-8"), hashlib.sha256).digest()
    region_key = hmac.new(date_key, region.encode("utf-8"), hashlib.sha256).digest()
    service_key = hmac.new(region_key, SERVICE.encode("utf-8"), hashlib.sha256).digest()
    return hmac.new(service_key, b"aws4_request", hashlib.sha256).digest()
