from __future__ import annotations
# noqa: SIZE_OK — stdlib SigV4 client kept together to avoid a backup framework dependency.

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import hmac
import os
from pathlib import Path
import re
from types import TracebackType
import xml.etree.ElementTree as ET
from typing import BinaryIO, Final, Protocol
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlparse, urlunparse
from urllib.request import HTTPRedirectHandler, Request, build_opener

from .redaction import redact_values
from .site_paths import read_env


def _current_paths():
    from .settings import PATHS as current_paths

    return current_paths


SERVICE: Final = "s3"
ALGORITHM: Final = "AWS4-HMAC-SHA256"
TRANSFER_CHUNK_SIZE: Final = 1024 * 1024
CONFIG_FILENAME: Final = "backup-storage.env"
PROFILE_DIRNAME: Final = "backup-storage.d"
PROFILE_RE: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,62}")
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
    allow_insecure: bool = False


class S3ConfigError(RuntimeError):
    pass


class Response(Protocol):
    status: int

    def read(self, size: int = -1) -> bytes:
        pass

    def __enter__(self) -> Response:
        pass

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> bool | None:
        pass


class Opener(Protocol):
    def __call__(self, request: Request, *, timeout: int) -> Response:
        pass


class _S3RedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        source = urlparse(req.full_url)
        target = urlparse(newurl)
        if source.scheme != target.scheme or (source.hostname, source.port) != (target.hostname, target.port):
            raise HTTPError(req.full_url, code, "refusing redirect to a different S3 host", headers, fp)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


_SAFE_OPENER = build_opener(_S3RedirectHandler())


def _safe_urlopen(request: Request, *, timeout: int) -> Response:
    return _SAFE_OPENER.open(request, timeout=timeout)


class S3Uploader:
    def __init__(self, opener: Opener | None = None) -> None:
        self._opener = opener or _safe_urlopen

    def upload_archive(self, config: S3Config, archive_path: Path, domain: str) -> str:
        key = s3_object_key(config.prefix, domain, archive_path.name)
        with archive_path.open("rb") as payload:
            payload_hash = _stream_digest(payload, "sha256")
            content_length = os.fstat(payload.fileno()).st_size
            payload.seek(0)
            request = _signed_request(
                config,
                "PUT",
                key,
                payload_hash,
                data=payload,
                content_length=content_length,
            )
            return self._upload(config, key, request)

    def upload_bytes(self, config: S3Config, key: str, payload: bytes) -> str:
        request = signed_request(config, "PUT", key, payload)
        return self._upload(config, key, request)

    def _upload(self, config: S3Config, key: str, request: Request) -> str:
        try:
            with self._opener(request, timeout=60) as response:
                status = getattr(response, "status", 200)
        except URLError as exc:
            raise OSError(str(exc.reason)) from exc
        if status >= 400:
            raise OSError(f"status {status}")
        return f"s3://{config.bucket}/{key}"

    def list_keys(self, config: S3Config, prefix: str) -> list[str]:
        query = f"list-type=2&prefix={quote(prefix, safe='/')}"
        request = signed_request(config, "GET", "", b"", query=query)
        try:
            with self._opener(request, timeout=60) as response:
                status = getattr(response, "status", 200)
                payload = response.read()
        except URLError as exc:
            raise OSError(str(exc.reason)) from exc
        if status >= 400:
            raise OSError(f"status {status}")
        root = ET.fromstring(payload)
        return [
            element.text or ""
            for element in root.findall(".//{*}Contents/{*}Key")
            if element.text
        ]

    def download_to_path(self, config: S3Config, key: str, destination: Path) -> Path:
        request = signed_request(config, "GET", key)
        try:
            with self._opener(request, timeout=60) as response:
                status = getattr(response, "status", 200)
                if status >= 400:
                    raise OSError(f"status {status}")
                headers = getattr(response, "headers", {})
                content_length = headers.get("Content-Length")
                expected_length = int(content_length) if content_length is not None else None
                downloaded = 0
                with os.fdopen(os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "wb") as output:
                    os.fchmod(output.fileno(), 0o600)
                    while chunk := response.read(TRANSFER_CHUNK_SIZE):
                        output.write(chunk)
                        downloaded += len(chunk)
                if expected_length is not None and downloaded != expected_length:
                    raise OSError(
                        f"incomplete download: expected {expected_length} bytes, got {downloaded}"
                    )
        except URLError as exc:
            raise OSError(str(exc.reason)) from exc
        return destination

    def delete_key(self, config: S3Config, key: str) -> str:
        request = signed_request(config, "DELETE", key)
        try:
            with self._opener(request, timeout=60) as response:
                status = getattr(response, "status", 204)
        except URLError as exc:
            raise OSError(str(exc.reason)) from exc
        if status >= 400:
            raise OSError(f"status {status}")
        return f"s3://{config.bucket}/{key}"


def _profile_name(profile: str | None) -> str | None:
    if profile in {None, "", "default"}:
        return None
    if not PROFILE_RE.fullmatch(profile):
        raise S3ConfigError("invalid backup storage profile")
    return profile


def s3_config_path(profile: str | None = None) -> Path:
    name = _profile_name(profile)
    if name is None:
        return Path(_current_paths().config_dir) / CONFIG_FILENAME
    return Path(_current_paths().config_dir) / PROFILE_DIRNAME / f"{name}.env"


def write_s3_config(config: S3Config, profile: str | None = None) -> Path:
    path = s3_config_path(profile)
    endpoint = _normalized_endpoint(config.endpoint, allow_insecure=config.allow_insecure)
    path.parent.mkdir(parents=True, exist_ok=True)
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w", encoding="utf-8") as output:
        os.fchmod(output.fileno(), 0o600)
        output.write(
            "\n".join([
                f"WPFY_BACKUP_S3_ENDPOINT={endpoint}",
                f"WPFY_BACKUP_S3_BUCKET={config.bucket}",
                f"WPFY_BACKUP_S3_REGION={config.region}",
                f"WPFY_BACKUP_S3_PREFIX={config.prefix.strip('/')}",
                f"WPFY_BACKUP_S3_ACCESS_KEY={config.access_key}",
                f"WPFY_BACKUP_S3_SECRET_KEY={config.secret_key}",
                f"WPFY_BACKUP_S3_ALLOW_INSECURE={'1' if config.allow_insecure else '0'}",
                "",
            ])
        )
    path.chmod(0o600)
    return path


def clear_s3_config(profile: str | None = None) -> None:
    path = s3_config_path(profile)
    if path.exists():
        path.unlink()


def load_s3_config(profile: str | None = None) -> S3Config:
    if _profile_name(profile) is None:
        env_config = _load_env_config()
        if env_config is not None:
            return env_config
    stored_config = _load_stored_config(profile)
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
    allow_insecure = os.environ.get("WPFY_BACKUP_S3_ALLOW_INSECURE", "").strip() == "1"
    return S3Config(
        endpoint=_normalized_endpoint(values["WPFY_BACKUP_S3_ENDPOINT"], allow_insecure=allow_insecure),
        bucket=values["WPFY_BACKUP_S3_BUCKET"],
        region=values["WPFY_BACKUP_S3_REGION"],
        prefix=os.environ.get("WPFY_BACKUP_S3_PREFIX", "").strip("/"),
        access_key=values["WPFY_BACKUP_S3_ACCESS_KEY"],
        secret_key=values["WPFY_BACKUP_S3_SECRET_KEY"],
        allow_insecure=allow_insecure,
    )


def _load_stored_config(profile: str | None = None) -> S3Config | None:
    path = s3_config_path(profile)
    try:
        values = {key: value.strip() for key, value in read_env(path).items()}
    except OSError as exc:
        raise S3ConfigError(f"cannot read backup storage config: {exc}") from exc
    if not values and not path.exists():
        return None
    missing = [key for key in REQUIRED_ENV if not values.get(key)]
    if missing:
        raise S3ConfigError(f"missing {', '.join(missing)}")
    allow_insecure = values.get("WPFY_BACKUP_S3_ALLOW_INSECURE", "").strip() == "1"
    return S3Config(
        endpoint=_normalized_endpoint(values["WPFY_BACKUP_S3_ENDPOINT"], allow_insecure=allow_insecure),
        bucket=values["WPFY_BACKUP_S3_BUCKET"],
        region=values["WPFY_BACKUP_S3_REGION"],
        prefix=values.get("WPFY_BACKUP_S3_PREFIX", "").strip("/"),
        access_key=values["WPFY_BACKUP_S3_ACCESS_KEY"],
        secret_key=values["WPFY_BACKUP_S3_SECRET_KEY"],
        allow_insecure=allow_insecure,
    )


def _normalized_endpoint(endpoint: str, *, allow_insecure: bool = False) -> str:
    normalized = endpoint.strip()
    if "://" not in normalized:
        normalized = f"https://{normalized}"
    parsed = urlparse(normalized)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise S3ConfigError("WPFY_BACKUP_S3_ENDPOINT must use http(s) and include a host")
    if parsed.scheme == "http" and not allow_insecure:
        raise S3ConfigError(
            "plaintext S3 endpoint rejected; use HTTPS or explicitly pass --allow-insecure "
            "(WPFY_BACKUP_S3_ALLOW_INSECURE=1)"
        )
    try:
        parsed.port
    except ValueError as exc:
        raise S3ConfigError("WPFY_BACKUP_S3_ENDPOINT has an invalid port") from exc
    return normalized.rstrip("/")


def s3_object_key(prefix: str, domain: str, archive_name: str) -> str:
    parts = [part for part in (prefix.strip("/"), domain, archive_name) if part]
    return "/".join(parts)


def redact_s3_secrets(message: str, config: S3Config) -> str:
    return redact_values(message, (config.access_key, config.secret_key))


def signed_put_request(config: S3Config, key: str, payload: bytes) -> Request:
    return signed_request(config, "PUT", key, payload)


def signed_request(config: S3Config, method: str, key: str = "", payload: bytes = b"", *, query: str = "") -> Request:
    return _signed_request(
        config,
        method,
        key,
        hashlib.sha256(payload).hexdigest(),
        data=payload if method in {"PUT", "POST"} else None,
        query=query,
    )


def _signed_request(
    config: S3Config,
    method: str,
    key: str,
    payload_hash: str,
    *,
    data: bytes | BinaryIO | None = None,
    content_length: int | None = None,
    query: str = "",
) -> Request:
    parsed = urlparse(_normalized_endpoint(config.endpoint, allow_insecure=config.allow_insecure))
    now = datetime.now(timezone.utc)
    date_stamp = now.strftime("%Y%m%d")
    amz_date = now.strftime("%Y%m%dT%H%M%SZ")
    encoded_bucket = quote(config.bucket, safe="")
    encoded_key = quote(key, safe="/")
    canonical_uri = f"{parsed.path.rstrip('/')}/{encoded_bucket}"
    if encoded_key:
        canonical_uri = f"{canonical_uri}/{encoded_key}"
    host = parsed.netloc
    headers = {
        "Host": host,
        "x-amz-content-sha256": payload_hash,
        "x-amz-date": amz_date,
    }
    if content_length is not None:
        headers["Content-Length"] = str(content_length)
    signed_headers = ";".join(name.lower() for name in sorted(headers))
    canonical_headers = "\n".join(f"{name.lower()}:{headers[name]}" for name in sorted(headers)) + "\n"
    canonical_request = "\n".join([
        method,
        canonical_uri,
        query,
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
    url = urlunparse((parsed.scheme, parsed.netloc, canonical_uri, "", query, ""))
    return Request(url, data=data, headers=headers, method=method)


def _stream_digest(source: BinaryIO, algorithm: str) -> str:
    digest = hashlib.new(algorithm)
    while chunk := source.read(TRANSFER_CHUNK_SIZE):
        digest.update(chunk)
    return digest.hexdigest()


def signing_key(secret_key: str, date_stamp: str, region: str) -> bytes:
    date_key = hmac.new(f"AWS4{secret_key}".encode("utf-8"), date_stamp.encode("utf-8"), hashlib.sha256).digest()
    region_key = hmac.new(date_key, region.encode("utf-8"), hashlib.sha256).digest()
    service_key = hmac.new(region_key, SERVICE.encode("utf-8"), hashlib.sha256).digest()
    return hmac.new(service_key, b"aws4_request", hashlib.sha256).digest()
