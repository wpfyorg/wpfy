"""Secure, transactional updater primitives.

This module intentionally has no CLI dependency.  A later CLI adapter can call
``Updater.status()``, ``Updater.check()``, ``Updater.apply()``, and
``Updater.rollback()`` and render the typed results below.
"""

from __future__ import annotations

import contextlib
import datetime as _datetime
import errno
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any, Callable, Iterator, Mapping, Protocol, Sequence
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from .settings import PATHS, WpfyPaths


class UpdateExitCode(IntEnum):
    """Update command exit code."""
    OK = 0
    ERROR = 1
    INVALID = 2
    BUSY = 3
    SIGNATURE = 10
    INTEGRITY = 11
    DOWNLOAD = 12
    STAGING = 13
    ACTIVATION = 14
    ROLLBACK = 15


class UpdaterError(Exception):
    """Base class for fail-closed updater errors."""

    exit_code = UpdateExitCode.ERROR


class ManifestError(UpdaterError):
    """Manifest validation error."""
    exit_code = UpdateExitCode.INVALID


class SignatureError(ManifestError):
    """Signature verification error."""
    exit_code = UpdateExitCode.SIGNATURE


class IntegrityError(UpdaterError):
    """Integrity check error."""
    exit_code = UpdateExitCode.INTEGRITY


class DownloadError(UpdaterError):
    """Download error."""
    exit_code = UpdateExitCode.DOWNLOAD


class StagingError(UpdaterError):
    """Staging error."""
    exit_code = UpdateExitCode.STAGING


class ActivationError(UpdaterError):
    """Activation error."""
    exit_code = UpdateExitCode.ACTIVATION


class RollbackError(UpdaterError):
    """Rollback error."""
    exit_code = UpdateExitCode.ROLLBACK


class BusyError(UpdaterError):
    """Update lock busy error."""
    exit_code = UpdateExitCode.BUSY


TRUST_FINGERPRINT = "9D6F1EE9B1162B410FDE04B38A71ABDD2CCD5FDE"
DEFAULT_RELEASE_REPOSITORY = "wpfyorg/wpfy"
DEFAULT_STABLE_MANIFEST_URL = (
    f"https://github.com/{DEFAULT_RELEASE_REPOSITORY}/releases/latest/download/wpfy-release.json"
)


@dataclass(frozen=True)
class SignatureResult:
    """Signature verification result."""
    verified: bool
    fingerprint: str = ""
    detail: str = ""

    def __bool__(self) -> bool:
        return self.verified


@dataclass(frozen=True)
class ReleaseManifest:
    """Release manifest."""
    schema: int
    product: str
    channel: str
    version: str
    published_at: str
    expires_at: str
    sequence: int
    wheel_url: str
    wheel_sha256: str
    wheel_size: int
    platform: dict[str, str]

    @property
    def tag(self) -> str:
        """Return version tag."""
        base, pre = self.version[:], ""
        match = re.fullmatch(r"(\d+\.\d+\.\d+)(a|b|rc)(\d+)", self.version)
        if match:
            base, pre = match.group(1), f"-{match.group(2)}{match.group(3)}"
        return f"v{base}{pre}"

    @property
    def prerelease(self) -> bool:
        """Check if prerelease version."""
        match = _SEMVER_RE.fullmatch(self.version)
        return bool(match and match.group("pre"))

    def as_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "schema": self.schema,
            "product": self.product,
            "channel": self.channel,
            "sequence": self.sequence,
            "generated_at": self.published_at,
            "expires_at": self.expires_at,
            "release": {
                "version": self.version,
                "prerelease": self.prerelease,
                "tag": self.tag,
                "platform": self.platform,
            },
            "artifact": {
                "name": Path(urlparse(self.wheel_url).path).name,
                "url": self.wheel_url,
                "sha256": self.wheel_sha256,
                "size": self.wheel_size,
            },
        }


@dataclass(frozen=True)
class UpdateState:
    """Update state."""
    active_version: str | None = None
    active_sequence: int = -1
    active_channel: str | None = None
    releases: tuple[dict[str, Any], ...] = ()
    last_outcome: str | None = None
    last_error: str | None = None
    updated_at: str | None = None
    channel_sequences: tuple[tuple[str, int], ...] = ()

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "UpdateState":
        """Create instance from mapping."""
        releases = value.get("releases", [])
        if not isinstance(releases, list) or not all(isinstance(item, dict) for item in releases):
            raise ManifestError("updater state has invalid releases")
        sequence = value.get("active_sequence", -1)
        if isinstance(sequence, bool) or not isinstance(sequence, int):
            raise ManifestError("updater state has invalid sequence")
        channel_sequences = value.get("channel_sequences", [])
        if not isinstance(channel_sequences, list):
            raise ManifestError("updater state has invalid channel floors")
        floors: list[tuple[str, int]] = []
        for item in channel_sequences:
            if not isinstance(item, list) or len(item) != 2 or item[0] not in _CHANNELS:
                raise ManifestError("updater state has invalid channel floor")
            if isinstance(item[1], bool) or not isinstance(item[1], int) or item[1] < 0:
                raise ManifestError("updater state has invalid channel floor")
            floors.append((item[0], item[1]))
        return cls(
            active_version=value.get("active_version"),
            active_sequence=sequence,
            active_channel=value.get("active_channel"),
            releases=tuple(dict(item) for item in releases),
            last_outcome=value.get("last_outcome"),
            last_error=value.get("last_error"),
            updated_at=value.get("updated_at"),
            channel_sequences=tuple(floors),
        )

    def as_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "active_version": self.active_version,
            "active_sequence": self.active_sequence,
            "active_channel": self.active_channel,
            "releases": list(self.releases),
            "last_outcome": self.last_outcome,
            "last_error": self.last_error,
            "updated_at": self.updated_at,
            "channel_sequences": [list(item) for item in self.channel_sequences],
        }


@dataclass(frozen=True)
class UpdateResult:
    """Update operation result."""
    exit_code: int
    message: str
    state: UpdateState
    version: str | None = None
    changed: bool = False
    rolled_back: bool = False

    @property
    def ok(self) -> bool:
        """Check if operation succeeded."""
        return self.exit_code == UpdateExitCode.OK

    @property
    def success(self) -> bool:
        """Check if operation was successful."""
        return self.ok


@dataclass(frozen=True)
class CheckResult:
    """Update check result."""
    manifest: ReleaseManifest | None
    state: UpdateState
    update_available: bool
    message: str
    exit_code: int = 0

    @property
    def ok(self) -> bool:
        """Check if operation succeeded."""
        return self.exit_code == UpdateExitCode.OK and self.manifest is not None


@dataclass(frozen=True)
class UpdaterConfig:
    """Updater configuration."""
    paths: WpfyPaths = PATHS
    product: str = "wpfy"
    manifest_url: str = field(default_factory=lambda: os.environ.get("WPFY_UPDATE_MANIFEST_URL", DEFAULT_STABLE_MANIFEST_URL))
    rc_manifest_url: str | None = field(default_factory=lambda: os.environ.get("WPFY_UPDATE_RC_MANIFEST_URL"))
    signature_url: str | None = field(default_factory=lambda: os.environ.get("WPFY_UPDATE_SIGNATURE_URL"))
    keyring_path: str | None = None
    signer_fingerprint: str = TRUST_FINGERPRINT
    allowlisted_hosts: tuple[str, ...] = ("github.com",)
    max_manifest_bytes: int = 128 * 1024
    max_wheel_bytes: int = 256 * 1024 * 1024
    retain_releases: int = 2
    python_executable: str = sys.executable
    supported_platform: str | None = field(default_factory=lambda: os.environ.get("WPFY_UPDATE_PLATFORM"))
    max_clock_skew_seconds: int = 300
    command_timeout_seconds: int = 120
    gpg_timeout_seconds: int = 30

    def __post_init__(self) -> None:
        if self.signature_url is None:
            object.__setattr__(self, "signature_url", self.manifest_url + ".asc")
        if self.keyring_path is None:
            object.__setattr__(self, "keyring_path", self.paths.update_keyring_path)
        if self.signer_fingerprint.replace(" ", "").upper() != TRUST_FINGERPRINT:
            raise ValueError("updater signer fingerprint is pinned")
        if isinstance(self.retain_releases, bool) or not isinstance(self.retain_releases, int) or self.retain_releases < 0:
            raise ValueError("retain_releases must be a non-negative integer")
        if self.command_timeout_seconds <= 0 or self.gpg_timeout_seconds <= 0:
            raise ValueError("updater timeouts must be positive")


class CommandRunner(Protocol):
    """Command runner interface."""
    def __call__(self, argv: Sequence[str]) -> Any: ...


class Fetcher(Protocol):
    """Remote resource fetcher interface."""
    def __call__(self, url: str, destination: Path, max_bytes: int) -> None: ...


_SEMVER_RE = re.compile(r"(?P<base>\d+\.\d+\.\d+)(?:(?P<pre>a|b|rc)(?P<number>\d+))?")
_TAG_RE = re.compile(r"v(?P<base>\d+\.\d+\.\d+)(?:-(?P<pre>a|b|rc)(?P<number>\d+))?")
_SHA256_RE = re.compile(r"[0-9a-fA-F]{64}")
_FINGERPRINT_RE = re.compile(r"[0-9A-Fa-f]{40}")
_CHANNELS = {"stable", "rc"}
_MANIFEST_KEYS = {"schema", "product", "channel", "sequence", "generated_at", "expires_at", "release", "artifact"}
_RELEASE_KEYS = {"version", "prerelease", "tag", "platform"}
_PLATFORM_KEYS = {"python", "abi", "platform"}
_ARTIFACT_KEYS = {"name", "url", "size", "sha256"}


def _now() -> _datetime.datetime:
    return _datetime.datetime.now(_datetime.timezone.utc)


def _timestamp(value: Any, field_name: str) -> _datetime.datetime:
    if not isinstance(value, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", value):
        raise ManifestError(f"{field_name} must be RFC3339 timestamp")
    try:
        parsed = _datetime.datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=_datetime.timezone.utc)
    except ValueError as exc:
        raise ManifestError(f"{field_name} must be RFC3339 timestamp") from exc
    if parsed.tzinfo is None:
        raise ManifestError(f"{field_name} must include timezone")
    return parsed.astimezone(_datetime.timezone.utc)


def _parse_json_strict(text: str) -> Any:
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        """Return key-value pairs."""
        result: dict[str, Any] = {}
        for key, value in items:
            if key in result:
                raise ManifestError(f"duplicate JSON key: {key}")
            result[key] = value
        return result

    def invalid_constant(value: str) -> Any:
        """Invalid constant."""
        raise ManifestError(f"invalid JSON constant: {value}")

    try:
        return json.loads(text, object_pairs_hook=pairs, parse_constant=invalid_constant)
    except json.JSONDecodeError as exc:
        raise ManifestError("manifest JSON is invalid") from exc


def _normal_platform(value: Any) -> str:
    if isinstance(value, str):
        result = value.lower()
    elif isinstance(value, dict) and set(value) == {"os", "arch"}:
        if not all(isinstance(item, str) for item in value.values()):
            raise ManifestError("platform fields must be strings")
        result = f"{value['os'].lower()}-{value['arch'].lower()}"
    else:
        raise ManifestError("platform must be string or {os, arch}")
    result = {"linux-amd64": "linux-x86_64", "linux-arm64": "linux-aarch64"}.get(result, result)
    if not re.fullmatch(r"[a-z0-9][a-z0-9._-]{1,63}", result):
        raise ManifestError("invalid platform")
    return result


def _https_url(value: Any, field_name: str, hosts: Sequence[str]) -> str:
    if not isinstance(value, str) or len(value) > 2048:
        raise ManifestError(f"{field_name} must be HTTPS URL")
    parsed = urlparse(value)
    host = (parsed.hostname or "").lower().rstrip(".")
    if parsed.scheme != "https" or not host or parsed.username or parsed.password:
        raise ManifestError(f"{field_name} must use HTTPS")
    if parsed.port not in (None, 443):
        raise ManifestError(f"{field_name} has disallowed port")
    allowed = {item.lower().rstrip(".") for item in hosts}
    if host not in allowed:
        raise ManifestError(f"{field_name} host is not allowlisted")
    if parsed.query or parsed.fragment:
        raise ManifestError(f"{field_name} cannot contain query or fragment")
    return value


def validate_manifest(
    payload: Mapping[str, Any],
    *,
    product: str = "wpfy",
    channel: str = "stable",
    allowlisted_hosts: Sequence[str] = ("github.com",),
    supported_platform: str | None = None,
    now: _datetime.datetime | None = None,
    max_clock_skew_seconds: int = 300,
) -> ReleaseManifest:
    """Strictly validate already-decoded manifest data."""
    if not isinstance(payload, Mapping) or set(payload) != _MANIFEST_KEYS:
        raise ManifestError("manifest schema keys are invalid")
    if payload.get("schema") != 1:
        raise ManifestError("unsupported manifest schema")
    if payload.get("product") != product:
        raise ManifestError("manifest product mismatch")
    if payload.get("channel") not in _CHANNELS or payload["channel"] != channel:
        raise ManifestError("manifest channel mismatch")
    sequence = payload.get("sequence")
    if isinstance(sequence, bool) or not isinstance(sequence, int) or sequence < 1:
        raise ManifestError("invalid manifest sequence")
    generated = _timestamp(payload.get("generated_at"), "generated_at")
    expires = _timestamp(payload.get("expires_at"), "expires_at")
    current = (now or _now()).astimezone(_datetime.timezone.utc)
    if expires <= current:
        raise ManifestError("manifest expired")
    if generated > current + _datetime.timedelta(seconds=max_clock_skew_seconds):
        raise ManifestError("manifest generation time is in the future")
    if expires <= generated:
        raise ManifestError("manifest expiry precedes generation")
    release = payload.get("release")
    if not isinstance(release, Mapping) or set(release) != _RELEASE_KEYS:
        raise ManifestError("release schema is invalid")
    version = release.get("version")
    match = _SEMVER_RE.fullmatch(version) if isinstance(version, str) else None
    if match is None:
        raise ManifestError("invalid semantic version")
    prerelease = release.get("prerelease")
    has_pre = match.group("pre") is not None
    if type(prerelease) is not bool or prerelease != has_pre:
        raise ManifestError("release prerelease does not match version")
    tag = release.get("tag")
    tag_match = _TAG_RE.fullmatch(tag) if isinstance(tag, str) else None
    expected_tag = f"v{match.group('base')}" + (f"-{match.group('pre')}{match.group('number')}" if has_pre else "")
    if tag_match is None or tag != expected_tag:
        raise ManifestError("release tag does not match version")
    if channel == "stable" and has_pre:
        raise ManifestError("stable channel cannot contain prerelease")
    if channel == "rc" and not has_pre:
        raise ManifestError("rc channel requires prerelease")
    platform_value = release.get("platform")
    if not isinstance(platform_value, Mapping) or set(platform_value) != _PLATFORM_KEYS:
        raise ManifestError("release platform schema is invalid")
    if any(not isinstance(item, str) or not item or any(char.isspace() for char in item) for item in platform_value.values()):
        raise ManifestError("release platform values are invalid")
    combined_platform = "-".join(str(platform_value[key]).lower() for key in ("python", "abi", "platform"))
    if (
        supported_platform is not None
        and str(platform_value["platform"]).lower() != "any"
        and supported_platform.lower() not in (combined_platform, str(platform_value["platform"]).lower())
    ):
        raise ManifestError("manifest platform mismatch")
    artifact = payload.get("artifact")
    if not isinstance(artifact, Mapping) or set(artifact) != _ARTIFACT_KEYS:
        raise ManifestError("artifact schema is invalid")
    name = artifact.get("name")
    if not isinstance(name, str) or Path(name).name != name or not name.endswith(".whl"):
        raise ManifestError("artifact name is invalid")
    wheel_url = _https_url(artifact.get("url"), "artifact.url", allowlisted_hosts)
    url_parts = [part for part in urlparse(wheel_url).path.split("/") if part]
    if Path(urlparse(wheel_url).path).name != name:
        raise ManifestError("artifact URL basename does not match name")
    if len(url_parts) < 4 or url_parts[-4:] != ["releases", "download", tag, name]:
        raise ManifestError("artifact URL is not an immutable release asset")
    digest = artifact.get("sha256")
    if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise ManifestError("artifact SHA-256 must be lowercase")
    size = artifact.get("size")
    if isinstance(size, bool) or not isinstance(size, int) or not 1 <= size <= 2**63 - 1:
        raise ManifestError("invalid artifact size")
    return ReleaseManifest(
        schema=1, product=product, channel=channel, version=str(version),
        published_at=payload["generated_at"], expires_at=payload["expires_at"],
        sequence=sequence, wheel_url=wheel_url, wheel_sha256=digest.lower(),
        wheel_size=size, platform=dict(platform_value),
    )


def _secure_existing(path: Path, *, root_owner: bool = False) -> os.stat_result:
    try:
        info = path.lstat()
    except FileNotFoundError as exc:
        raise UpdaterError(f"secure path does not exist: {path}") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise UpdaterError(f"secure path is not a regular file: {path}")
    if info.st_mode & 0o022:
        raise UpdaterError(f"secure path is writable by group or others: {path}")
    if root_owner and info.st_uid != 0:
        raise UpdaterError(f"secure path is not root-owned: {path}")
    return info


def _secure_dir(path: Path, mode: int = 0o750) -> None:
    path = path.absolute()
    # Check before mkdir(parents=True): mkdir otherwise follows an attacker
    # supplied parent symlink and the later check would be too late.
    current = path
    ancestors: list[Path] = []
    while current != current.parent:
        ancestors.append(current)
        current = current.parent
    for ancestor in reversed(ancestors):
        if ancestor.is_symlink() and ancestor not in (Path("/var"), Path("/tmp")):
            raise UpdaterError(f"secure directory is a symlink: {ancestor}")
    path.mkdir(parents=True, exist_ok=True, mode=mode)
    current = path
    while True:
        if current.is_symlink():
            # macOS exposes /var and /tmp as compatibility symlinks; Linux
            # production paths remain checked all the way to their parent.
            if current in (Path("/var"), Path("/tmp")):
                break
            raise UpdaterError(f"secure directory is a symlink: {current}")
        if current not in (Path("/"), Path("/tmp"), Path("/var")):
            info = current.lstat()
            if info.st_mode & 0o022:
                raise UpdaterError(f"secure directory is writable by group or others: {current}")
            if os.geteuid() == 0 and info.st_uid != 0:
                raise UpdaterError(f"secure directory is not root-owned: {current}")
        if current == current.parent:
            break
        # Stop checking once outside configured private tree; this also keeps
        # ordinary /tmp parents usable in unprivileged tests.
        current = current.parent
        if str(current) in ("/", ""):
            break
    os.chmod(path, mode)


def _open_nofollow(path: Path, flags: int, mode: int = 0o640) -> int:
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    try:
        return os.open(path, flags | nofollow, mode)
    except OSError as exc:
        if exc.errno in (errno.ELOOP, errno.EMLINK):
            raise UpdaterError(f"secure path is a symlink: {path}") from exc
        raise


def _fsync_directory(path: Path) -> None:
    fd = _open_nofollow(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def atomic_write_json(path: str | Path, value: Mapping[str, Any], *, mode: int = 0o640) -> None:
    """Write JSON with file and containing-directory durability."""
    target = Path(path)
    _secure_dir(target.parent)
    if target.exists() or target.is_symlink():
        if target.is_symlink():
            raise UpdaterError(f"refusing to replace symlink: {target}")
        _secure_existing(target, root_owner=(os.geteuid() == 0))
    fd, temporary = tempfile.mkstemp(prefix=f".{target.name}.", dir=target.parent)
    temporary_path = Path(temporary)
    try:
        os.fchmod(fd, mode)
        data = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.write(b"\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary_path, target)
        directory_fd = os.open(target.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except Exception:
        with contextlib.suppress(FileNotFoundError):
            temporary_path.unlink()
        raise


def read_state(path: str | Path) -> UpdateState:
    """Read state."""
    target = Path(path)
    if not target.exists() and not target.is_symlink():
        return UpdateState()
    _secure_existing(target, root_owner=(os.geteuid() == 0))
    if target.stat().st_size > 128 * 1024:
        raise ManifestError("updater state is too large")
    try:
        fd = _open_nofollow(target, os.O_RDONLY)
        with os.fdopen(fd, "r", encoding="utf-8") as stream:
            value = _parse_json_strict(stream.read())
    except (OSError, ValueError, UpdaterError) as exc:
        raise ManifestError("updater state is unreadable") from exc
    if not isinstance(value, dict):
        raise ManifestError("updater state is not an object")
    return UpdateState.from_mapping(value)


def verify_manifest_signature(
    manifest_path: str | Path,
    signature_path: str | Path,
    keyring_path: str | Path,
    expected_fingerprint: str,
    *,
    runner: CommandRunner | None = None,
    timeout_seconds: int = 30,
) -> SignatureResult:
    """Verify detached signature before opening/parsing manifest JSON."""
    manifest = Path(manifest_path)
    signature = Path(signature_path)
    keyring = Path(keyring_path)
    _secure_existing(manifest, root_owner=(os.geteuid() == 0))
    _secure_existing(signature, root_owner=(os.geteuid() == 0))
    _secure_existing(keyring, root_owner=(os.geteuid() == 0))
    expected = expected_fingerprint.replace(" ", "").upper()
    if not _FINGERPRINT_RE.fullmatch(expected):
        raise SignatureError("expected signer fingerprint is invalid")
    if expected != TRUST_FINGERPRINT:
        raise SignatureError("signer fingerprint is not the pinned updater key")
    command = ("gpgv", "--status-fd", "1", "--keyring", str(keyring), str(signature), str(manifest))
    execute = runner or (lambda argv: subprocess.run(
        argv, capture_output=True, text=True, check=False, timeout=timeout_seconds
    ))
    try:
        completed = execute(command)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise SignatureError(f"gpgv failed to execute: {exc}") from exc
    returncode = getattr(completed, "returncode", 1)
    stdout = getattr(completed, "stdout", "") or ""
    stderr = getattr(completed, "stderr", "") or ""
    if isinstance(stdout, bytes):
        stdout = stdout.decode("utf-8", "replace")
    if isinstance(stderr, bytes):
        stderr = stderr.decode("utf-8", "replace")
    signatures: list[tuple[str, str]] = []
    for line in stdout.splitlines():
        fields = line.split()
        if len(fields) >= 3 and fields[0] == "[GNUPG:]" and fields[1] == "VALIDSIG":
            signature_fingerprint = fields[2].upper()
            # VALIDSIG ends with primary-key fingerprint.  Older gpg status
            # output may omit it when the signature itself is primary.
            primary_fingerprint = fields[-1].upper() if len(fields) >= 12 else signature_fingerprint
            signatures.append((signature_fingerprint, primary_fingerprint))
    if returncode != 0 or not any(primary == expected for _signature, primary in signatures):
        detail = stderr.strip() or "signature or signer fingerprint rejected"
        return SignatureResult(False, signatures[0][0] if signatures else "", detail)
    return SignatureResult(True, expected, "signature verified")


def load_signed_manifest(
    manifest_path: str | Path,
    signature_path: str | Path,
    config: UpdaterConfig,
    *,
    channel: str = "stable",
    runner: CommandRunner | None = None,
    now: _datetime.datetime | None = None,
) -> ReleaseManifest:
    """Load signed manifest."""
    result = verify_manifest_signature(
        manifest_path, signature_path, config.keyring_path or "", config.signer_fingerprint,
        runner=runner, timeout_seconds=config.gpg_timeout_seconds,
    )
    if not result:
        raise SignatureError(result.detail)
    path = Path(manifest_path)
    if path.stat().st_size > config.max_manifest_bytes:
        raise ManifestError("manifest exceeds size limit")
    try:
        payload = _parse_json_strict(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        raise ManifestError("manifest JSON is invalid") from exc
    return validate_manifest(
        payload, product=config.product, channel=channel, allowlisted_hosts=config.allowlisted_hosts,
        supported_platform=config.supported_platform, now=now,
        max_clock_skew_seconds=config.max_clock_skew_seconds,
    )


def stream_download(
    url: str,
    destination: str | Path,
    *,
    expected_size: int,
    expected_sha256: str,
    max_bytes: int,
    opener: Callable[..., Any] | None = None,
) -> None:
    """Bounded streaming download with atomic destination completion."""
    target = Path(destination)
    _secure_dir(target.parent)
    if target.exists() or target.is_symlink():
        raise DownloadError(f"download destination already exists: {target}")
    parsed = urlparse(url)
    if parsed.scheme != "https" or not parsed.hostname:
        raise DownloadError("download URL must use HTTPS")
    fd, temporary_name = tempfile.mkstemp(prefix=f".{target.name}.", suffix=".download", dir=target.parent)
    os.close(fd)
    temporary = Path(temporary_name)
    digest = hashlib.sha256()
    total = 0
    open_url = opener or urlopen
    try:
        request = Request(url, headers={"User-Agent": "wpfy-updater/1"})
        source = open_url(url if opener is not None else request, timeout=30)
        with source as response, temporary.open("wb") as stream:
            advertised = getattr(response, "headers", {}).get("Content-Length")
            if advertised and (not advertised.isdigit() or int(advertised) > max_bytes):
                raise DownloadError("download content length exceeds limit")
            while True:
                chunk = response.read(64 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > max_bytes or total > expected_size:
                    raise DownloadError("download exceeds declared size")
                digest.update(chunk)
                stream.write(chunk)
            stream.flush()
            os.fsync(stream.fileno())
        if total != expected_size:
            raise IntegrityError("download size mismatch")
        if digest.hexdigest() != expected_sha256.lower():
            raise IntegrityError("download SHA-256 mismatch")
        os.chmod(temporary, 0o640)
        os.replace(temporary, target)
        _fsync_directory(target.parent)
    except UpdaterError:
        with contextlib.suppress(FileNotFoundError):
            temporary.unlink()
        raise
    except Exception as exc:
        with contextlib.suppress(FileNotFoundError):
            temporary.unlink()
        raise DownloadError(f"download failed: {exc}") from exc


def _stream_unverified(url: str, destination: Path, max_bytes: int) -> None:
    """Bounded transport helper; callers verify content when metadata exists."""
    target = Path(destination)
    _secure_dir(target.parent)
    if target.exists() or target.is_symlink():
        raise DownloadError(f"download destination already exists: {target}")
    parsed = urlparse(url)
    if parsed.scheme != "https" or not parsed.hostname:
        raise DownloadError("download URL must use HTTPS")
    fd, temporary_name = tempfile.mkstemp(prefix=f".{target.name}.", suffix=".transport", dir=target.parent)
    os.close(fd)
    temporary = Path(temporary_name)
    try:
        total = 0
        with urlopen(Request(url, headers={"User-Agent": "wpfy-updater/1"}), timeout=30) as response, temporary.open("wb") as stream:
            advertised = getattr(response, "headers", {}).get("Content-Length")
            if advertised and (not advertised.isdigit() or int(advertised) > max_bytes):
                raise DownloadError("download content length exceeds limit")
            while True:
                chunk = response.read(64 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > max_bytes:
                    raise DownloadError("download exceeds size limit")
                stream.write(chunk)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o640)
        os.replace(temporary, target)
        _fsync_directory(target.parent)
    except UpdaterError:
        with contextlib.suppress(FileNotFoundError):
            temporary.unlink()
        raise
    except Exception as exc:
        with contextlib.suppress(FileNotFoundError):
            temporary.unlink()
        raise DownloadError(f"download failed: {exc}") from exc


def _command_ok(result: Any) -> bool:
    if isinstance(result, bool):
        return result
    return getattr(result, "returncode", 0) == 0


def _default_runner(argv: Sequence[str]) -> Any:
    return subprocess.run(argv, capture_output=True, text=True, check=False)


def _release_name(manifest: ReleaseManifest) -> str:
    safe_version = manifest.version.replace("+", "_")
    return f"{manifest.sequence}-{safe_version}"


def _version_key(version: str) -> tuple[int, int, int, int, int]:
    match = _SEMVER_RE.fullmatch(version)
    if match is None:
        raise ManifestError("invalid semantic version")
    pre = match.group("pre")
    # Stable releases sort after all prereleases of same base.
    pre_rank = {None: 3, "rc": 2, "b": 1, "a": 0}[pre]
    return (int(match.group("base").split(".")[0]), int(match.group("base").split(".")[1]), int(match.group("base").split(".")[2]), pre_rank, int(match.group("number") or 0))


def _channel_floor(state: UpdateState, channel: str) -> int:
    explicit = max((sequence for name, sequence in state.channel_sequences if name == channel), default=-1)
    if explicit < 0 and state.active_channel == channel:
        return state.active_sequence
    return explicit


def _validate_progress(state: UpdateState, manifest: ReleaseManifest) -> None:
    if manifest.sequence <= _channel_floor(state, manifest.channel):
        raise ManifestError(f"{manifest.channel} manifest sequence is not newer than replay floor")
    if state.active_version is not None and _version_key(manifest.version) < _version_key(state.active_version):
        raise ManifestError("manifest version is lower than active release")


def _read_link_target(link: Path, root: Path) -> Path | None:
    if not link.exists() and not link.is_symlink():
        return None
    if not link.is_symlink():
        raise ActivationError(f"current path is not a symlink: {link}")
    if os.geteuid() == 0 and link.lstat().st_uid != 0:
        raise ActivationError("current symlink is not root-owned")
    raw = os.readlink(link)
    raw_target = link.parent / raw
    if raw_target.is_symlink():
        raise ActivationError("current symlink target must be a real release directory")
    target = raw_target.resolve(strict=False)
    root_resolved = root.resolve(strict=False)
    if target == root_resolved or root_resolved not in target.parents:
        raise ActivationError("current symlink escapes release directory")
    if target.is_symlink() or not target.is_dir():
        raise ActivationError("current symlink target is missing")
    info = target.lstat()
    if info.st_mode & 0o022 or (os.geteuid() == 0 and info.st_uid != 0):
        raise ActivationError("current release ownership or mode is unsafe")
    return target


def _safe_release_path(root: Path, name: Any) -> Path:
    if not isinstance(name, str) or not name or Path(name).name != name or name in {".", ".."}:
        raise ActivationError("release state contains invalid candidate")
    root_resolved = root.resolve(strict=False)
    candidate = root / name
    resolved = candidate.resolve(strict=False)
    if resolved != root_resolved and root_resolved not in resolved.parents:
        raise ActivationError("release candidate escapes release directory")
    if candidate.is_symlink() or not candidate.is_dir():
        raise ActivationError("release candidate is not a directory")
    info = candidate.lstat()
    if info.st_mode & 0o022 or (os.geteuid() == 0 and info.st_uid != 0):
        raise ActivationError("release candidate ownership or mode is unsafe")
    return candidate


def _require_contained(child: Path, parent: Path, label: str) -> None:
    child_abs = os.path.abspath(str(child))
    parent_abs = os.path.abspath(str(parent))
    if os.path.commonpath((child_abs, parent_abs)) != parent_abs:
        raise UpdaterError(f"{label} escapes configured root")


def _validate_layout(paths: WpfyPaths) -> None:
    _require_contained(Path(paths.releases_dir), Path(paths.install_root), "release directory")
    _require_contained(Path(paths.current_link), Path(paths.install_root), "current link")
    _require_contained(Path(paths.updater_dir), Path(paths.state_dir), "updater state")


def _atomic_symlink(target: Path, link: Path) -> None:
    _secure_dir(link.parent)
    if link.exists() and not link.is_symlink():
        raise ActivationError(f"refusing to replace non-symlink activation path: {link}")
    if link.is_symlink() and os.geteuid() == 0 and link.lstat().st_uid != 0:
        raise ActivationError("refusing to replace non-root-owned activation symlink")
    temporary = link.parent / f".{link.name}.{os.getpid()}.link"
    with contextlib.suppress(FileNotFoundError):
        temporary.unlink()
    os.symlink(os.path.relpath(target, link.parent), temporary)
    os.replace(temporary, link)
    directory_fd = os.open(link.parent, os.O_RDONLY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def migrate_legacy_install(
    paths: WpfyPaths = PATHS,
    *,
    now: _datetime.datetime | None = None,
    _lock_held: bool = False,
) -> Path | None:
    """Convert ``app``/``venv`` layout to one retained legacy release.

    Existing paths become compatibility symlinks, so old service units and the
    existing binary continue to work while ``current`` becomes the activation
    point for future releases.
    """
    if not _lock_held:
        with _UpdateLock(Path(paths.update_lock_path)):
            return migrate_legacy_install(paths, now=now, _lock_held=True)
    install = Path(paths.install_root)
    _validate_layout(paths)
    releases = Path(paths.releases_dir)
    current = Path(paths.current_link)
    app = Path(paths.app_dir)
    venv = install / "venv"
    if current.is_symlink():
        return _read_link_target(current, releases)
    if current.exists():
        raise ActivationError("cannot migrate over non-symlink current path")
    if app.is_symlink() or venv.is_symlink():
        raise ActivationError("legacy compatibility path is unexpectedly a symlink")
    if not app.exists() and not venv.exists():
        return None
    _secure_dir(install)
    _secure_dir(releases)
    stamp = (now or _now()).strftime("%Y%m%d%H%M%S")
    release = releases / f"legacy-{stamp}-{os.getpid()}"
    release.mkdir(mode=0o750, exist_ok=False)
    try:
        if app.exists():
            os.replace(app, release / "app")
        if venv.exists():
            os.replace(venv, release / "venv")
        _atomic_symlink(release, current)
        if (release / "app").exists():
            _atomic_symlink(release / "app", app)
        if (release / "venv").exists():
            _atomic_symlink(release / "venv", venv)
        _fsync_directory(release)
        _fsync_directory(releases)
        return release
    except BaseException:
        # Restore moved legacy paths if activation did not complete.
        with contextlib.suppress(FileNotFoundError):
            current.unlink()
        for name, original in (("app", app), ("venv", venv)):
            moved = release / name
            if moved.exists() and not original.exists():
                os.replace(moved, original)
        shutil.rmtree(release, ignore_errors=True)
        raise


class _UpdateLock:
    def __init__(self, path: Path):
        self.path = path
        self.handle: Any = None

    def __enter__(self) -> "_UpdateLock":
        _secure_dir(self.path.parent)
        if self.path.is_symlink():
            raise BusyError("updater lock path is a symlink")
        if self.path.exists():
            _secure_existing(self.path, root_owner=(os.geteuid() == 0))
        try:
            fd = _open_nofollow(self.path, os.O_RDWR | os.O_CREAT, 0o640)
            self.handle = os.fdopen(fd, "a+")
        except OSError as exc:
            raise BusyError("updater lock is unavailable") from exc
        os.chmod(self.path, 0o640)
        try:
            fcntl.flock(self.handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            self.handle.close()
            self.handle = None
            if exc.errno in (errno.EACCES, errno.EAGAIN):
                raise BusyError("another updater operation is active") from exc
            raise
        return self

    def __exit__(self, *_exc: Any) -> None:
        if self.handle is not None:
            fcntl.flock(self.handle.fileno(), fcntl.LOCK_UN)
            self.handle.close()


class Updater:
    """Transactional updater service with injectable system seams."""

    def __init__(
        self,
        config: UpdaterConfig | None = None,
        *,
        runner: CommandRunner | None = None,
        fetcher: Fetcher | None = None,
        clock: Callable[[], _datetime.datetime] = _now,
        staged_smoke: Callable[[Path, ReleaseManifest], None] | None = None,
        active_smoke: Callable[[Path, ReleaseManifest], None] | None = None,
    ) -> None:
        self.config = config or UpdaterConfig()
        _validate_layout(self.config.paths)
        self.runner = runner or _default_runner
        self.fetcher = fetcher or _stream_unverified
        self.clock = clock
        self.staged_smoke = staged_smoke or self._default_smoke
        self.active_smoke = active_smoke or self._default_smoke

    @property
    def paths(self) -> WpfyPaths:
        """Paths."""
        return self.config.paths

    def status(self) -> UpdateState:
        """Return status."""
        return read_state(self.paths.update_state_path)

    def _save_state(self, state: UpdateState) -> None:
        atomic_write_json(self.paths.update_state_path, state.as_dict())

    def _recover_locked(self) -> None:
        """Complete or compensate an interrupted transaction deterministically."""
        releases = Path(self.paths.releases_dir)
        if releases.exists() and not releases.is_symlink():
            for item in releases.iterdir():
                if item.name.startswith(".") and item.is_dir() and not item.is_symlink():
                    shutil.rmtree(item, ignore_errors=True)
        state = self.status()
        if state.last_outcome == "prepared":
            self._save_state(_state_after_failure(state, "recovered-before-activation", "interrupted before activation", self.clock()))
            return
        if state.last_outcome == "rollback-pending":
            for item in state.releases:
                if item.get("version") == state.active_version:
                    _atomic_symlink(_safe_release_path(releases, item.get("name")), Path(self.paths.current_link))
                    self._save_state(_state_after_failure(state, "recovered-rollback", "interrupted rollback", self.clock()))
                    return
            raise RollbackError("interrupted rollback has no active release target")
        if state.last_outcome != "activated-pending-health":
            return
        current = _read_link_target(Path(self.paths.current_link), releases)
        previous: Path | None = None
        for item in state.releases:
            if item.get("version") != state.active_version:
                previous = _safe_release_path(releases, item.get("name"))
                break
        if previous is None:
            link = Path(self.paths.current_link)
            if link.is_symlink():
                link.unlink()
            recovered = UpdateState(
                None, -1, None, state.releases, "recovered-rollback",
                "interrupted first activation had no previous release", self.clock().isoformat(),
                state.channel_sequences,
            )
            self._save_state(recovered)
            return
        _atomic_symlink(previous, Path(self.paths.current_link))
        self._save_state(_state_after_failure(state, "recovered-rollback", "interrupted post-activation health check", self.clock()))

    def _manifest_paths(self, work: Path, channel: str) -> tuple[Path, Path]:
        manifest = work / "manifest.json"
        signature = work / "manifest.json.asc"
        if channel == "rc" and not self.config.rc_manifest_url and self.config.manifest_url == DEFAULT_STABLE_MANIFEST_URL:
            raise ManifestError("rc manifest URL is not configured")
        manifest_url = self.config.rc_manifest_url if channel == "rc" and self.config.rc_manifest_url else self.config.manifest_url
        _https_url(manifest_url, "manifest URL", self.config.allowlisted_hosts)
        signature_url = self.config.signature_url if channel == "stable" else None
        signature_url = signature_url or manifest_url + ".asc"
        _https_url(signature_url, "signature URL", self.config.allowlisted_hosts)
        self._download(manifest_url, manifest, self.config.max_manifest_bytes)
        self._download(signature_url, signature, 64 * 1024)
        return manifest, signature

    def _download(self, url: str, destination: Path, limit: int) -> None:
        try:
            self.fetcher(url, destination, limit)
        except TypeError:
            # Small test doubles often expose url,destination only.
            self.fetcher(url, destination)  # type: ignore[misc]

    def _load(self, channel: str, manifest_path: Path | None, signature_path: Path | None) -> ReleaseManifest:
        if channel not in _CHANNELS:
            raise ManifestError("channel must be stable or rc")
        config = self.config
        if manifest_path is None or signature_path is None:
            _secure_dir(Path(config.paths.updater_dir))
            work = Path(tempfile.mkdtemp(prefix="check-", dir=config.paths.updater_dir))
            try:
                manifest_path, signature_path = self._manifest_paths(work, channel)
                return _load_with_channel(manifest_path, signature_path, config, channel, self.runner, self.clock())
            finally:
                shutil.rmtree(work, ignore_errors=True)
        # Config is immutable; channel is an operation selection, not a mutable
        # branch.  Keep validation bound to this exact requested channel.
        return _load_with_channel(manifest_path, signature_path, config, channel, self.runner, self.clock())

    def check(
        self,
        channel: str = "stable",
        *,
        manifest_path: str | Path | None = None,
        signature_path: str | Path | None = None,
    ) -> CheckResult:
        """Check."""
        state = self.status()
        try:
            manifest = self._load(channel, Path(manifest_path) if manifest_path else None, Path(signature_path) if signature_path else None)
        except UpdaterError as exc:
            return CheckResult(None, state, False, str(exc), int(exc.exit_code))
        available = manifest.sequence > _channel_floor(state, manifest.channel)
        return CheckResult(manifest, state, available, "update available" if available else "already current")

    def apply(
        self,
        channel: str = "stable",
        *,
        manifest_path: str | Path | None = None,
        signature_path: str | Path | None = None,
        wheel_path: str | Path | None = None,
    ) -> UpdateResult:
        """Apply changes."""
        try:
            with _UpdateLock(Path(self.paths.update_lock_path)):
                self._recover_locked()
                before = self.status()
                manifest = self._load(channel, Path(manifest_path) if manifest_path else None, Path(signature_path) if signature_path else None)
                _validate_progress(before, manifest)
                # Manifest authentication and replay/version checks complete
                # before touching legacy installation paths.
                migrate_legacy_install(self.paths, now=self.clock(), _lock_held=True)
                releases = Path(self.paths.releases_dir)
                _secure_dir(releases)
                self._save_state(_state_after_failure(before, "prepared", "release prepared", self.clock()))
                staging = Path(tempfile.mkdtemp(prefix=f".{_release_name(manifest)}.", dir=releases))
                try:
                    wheel = staging / "package.whl"
                    if wheel_path is None:
                        self._download(manifest.wheel_url, wheel, self.config.max_wheel_bytes)
                        # Generic fetchers cannot know manifest digest; default
                        # fetch path is replaced with explicit verification here.
                        if wheel.stat().st_size != manifest.wheel_size or _sha256(wheel) != manifest.wheel_sha256:
                            raise IntegrityError("downloaded wheel failed manifest verification")
                    else:
                        _copy_verified_wheel(Path(wheel_path), wheel, manifest, self.config.max_wheel_bytes)
                    release = staging / "release"
                    self._stage_release(manifest, wheel, release)
                    self.staged_smoke(release, manifest)
                    final = releases / _release_name(manifest)
                    if final.exists() or final.is_symlink():
                        raise ActivationError("release version already exists")
                    os.replace(release, final)
                    _fsync_directory(releases)
                    old = _read_link_target(Path(self.paths.current_link), releases)
                    _atomic_symlink(final, Path(self.paths.current_link))
                    pending = _state_after_activation(
                        before, manifest, final, old, self.clock(), outcome="activated-pending-health"
                    )
                    try:
                        self._save_state(pending)
                    except Exception as exc:
                        if old is not None:
                            _atomic_symlink(old, Path(self.paths.current_link))
                        else:
                            with contextlib.suppress(FileNotFoundError):
                                Path(self.paths.current_link).unlink()
                        raise ActivationError("activation journal was not durable; rolled back") from exc
                    try:
                        self.active_smoke(final, manifest)
                    except Exception as exc:
                        if old is not None:
                            _atomic_symlink(old, Path(self.paths.current_link))
                        else:
                            with contextlib.suppress(FileNotFoundError):
                                Path(self.paths.current_link).unlink()
                        failed = _state_after_failure(
                            before, "activation-rollback", "post-activation health check failed", self.clock(),
                            channel_sequences=pending.channel_sequences,
                        )
                        self._save_state(failed)
                        raise ActivationError(f"activation failed and was rolled back: {exc}") from exc
                    updated = _state_after_activation(before, manifest, final, old, self.clock())
                    try:
                        self._save_state(updated)
                    except Exception as exc:
                        # Activation is not committed until durable state is
                        # present. Restore old pointer if state persistence fails.
                        if old is not None:
                            _atomic_symlink(old, Path(self.paths.current_link))
                        else:
                            with contextlib.suppress(FileNotFoundError):
                                Path(self.paths.current_link).unlink()
                        raise ActivationError(f"activation state was not durable: {exc}") from exc
                    _prune_releases(releases, self.config.retain_releases, keep={final, old} if old else {final})
                    return UpdateResult(int(UpdateExitCode.OK), "update activated", updated, manifest.version, True)
                finally:
                    shutil.rmtree(staging, ignore_errors=True)
        except UpdaterError as exc:
            with contextlib.suppress(Exception):
                state = self.status()
                if state.last_outcome == "prepared":
                    self._save_state(_state_after_failure(state, "failed-before-activation", "staging or download failed", self.clock()))
            rolled_back = isinstance(exc, ActivationError) and (
                "rolled back" in str(exc) or "not durable" in str(exc)
            )
            return UpdateResult(int(exc.exit_code), str(exc), self.status(), changed=False, rolled_back=rolled_back)
        except Exception:
            return UpdateResult(int(UpdateExitCode.ERROR), "updater operation failed", self.status(), changed=False)

    def rollback(self, version: str | None = None) -> UpdateResult:
        """Rollback changes."""
        try:
            with _UpdateLock(Path(self.paths.update_lock_path)):
                self._recover_locked()
                state = self.status()
                releases = Path(self.paths.releases_dir)
                current = _read_link_target(Path(self.paths.current_link), releases)
                candidate: Path | None = None
                for item in state.releases:
                    if item.get("version") == version or (version is None and item.get("version") != state.active_version):
                        candidate = _safe_release_path(releases, item.get("name"))
                        break
                if candidate is None:
                    raise RollbackError("no retained release available for rollback")
                self._save_state(_state_after_failure(state, "rollback-prepared", "rollback prepared", self.clock()))
                manifest = ReleaseManifest(
                    1, self.config.product, str(next((x.get("channel", "stable") for x in state.releases if x.get("name") == candidate.name), "stable")),
                    str(next((x.get("version") for x in state.releases if x.get("name") == candidate.name), candidate.name)),
                    "1970-01-01T00:00:00Z", "9999-12-31T23:59:59Z", -1,
                    f"https://github.com/{DEFAULT_RELEASE_REPOSITORY}/releases/download/rollback/rollback.whl",
                    "0" * 64, 1,
                    {"python": "py3", "abi": "none", "platform": "any"},
                )
                self.active_smoke(candidate, manifest)
                _atomic_symlink(candidate, Path(self.paths.current_link))
                pending = _state_after_failure(state, "rollback-pending", "rollback pointer activated", self.clock())
                self._save_state(pending)
                updated = UpdateState(
                    active_version=next((x.get("version") for x in state.releases if x.get("name") == candidate.name), candidate.name),
                    active_sequence=next((int(x.get("sequence", -1)) for x in state.releases if x.get("name") == candidate.name), -1),
                    active_channel=next((x.get("channel") for x in state.releases if x.get("name") == candidate.name), "stable"),
                    releases=state.releases, last_outcome="rollback", last_error=None, updated_at=self.clock().isoformat(),
                    channel_sequences=state.channel_sequences,
                )
                _fsync_directory(releases)
                self._save_state(updated)
                return UpdateResult(0, "rollback activated", updated, updated.active_version, True)
        except UpdaterError as exc:
            with contextlib.suppress(Exception):
                state = self.status()
                if state.last_outcome == "rollback-prepared":
                    self._save_state(_state_after_failure(state, "rollback-failed", "rollback failed before activation", self.clock()))
            return UpdateResult(int(exc.exit_code), str(exc), self.status())
        except Exception:
            return UpdateResult(int(UpdateExitCode.ERROR), "rollback operation failed", self.status())

    def _stage_release(self, manifest: ReleaseManifest, wheel: Path, release: Path) -> None:
        try:
            _secure_dir(release)
            venv = release / "venv"
            result = self._run((self.config.python_executable, "-m", "venv", str(venv)))
            if not _command_ok(result):
                raise StagingError("python venv creation failed")
            pip = venv / "bin" / "pip"
            result = self._run((str(pip), "--isolated", "install", "--no-index", "--no-deps", str(wheel)))
            if not _command_ok(result):
                raise StagingError("offline wheel installation failed")
            atomic_write_json(release / "release.json", manifest.as_dict())
            _fsync_directory(release)
        except StagingError:
            raise
        except Exception as exc:
            raise StagingError(f"staging failed: {exc}") from exc

    def _default_smoke(self, release: Path, _manifest: ReleaseManifest) -> None:
        python = release / "venv" / "bin" / "python"
        result = self._run((str(python), "-c", "import wpfy; assert getattr(wpfy, '__version__', '')"))
        if not _command_ok(result):
            raise StagingError("staged smoke check failed")
        wrapper = release / "venv" / "bin" / "wpfy"
        result = self._run((str(wrapper), "--version"))
        if not _command_ok(result):
            raise StagingError("active wrapper health check failed")

    def _run(self, argv: Sequence[str]) -> Any:
        if self.runner is _default_runner:
            try:
                return subprocess.run(
                    argv, capture_output=True, text=True, check=False,
                    timeout=self.config.command_timeout_seconds,
                )
            except subprocess.TimeoutExpired as exc:
                raise StagingError("updater command timed out") from exc
        return self.runner(argv)


def _load_with_channel(path: Path, signature: Path, config: UpdaterConfig, channel: str, runner: CommandRunner, now: _datetime.datetime) -> ReleaseManifest:
    result = verify_manifest_signature(
        path, signature, config.keyring_path or "", config.signer_fingerprint,
        runner=runner, timeout_seconds=config.gpg_timeout_seconds,
    )
    if not result:
        raise SignatureError(result.detail)
    if path.stat().st_size > config.max_manifest_bytes:
        raise ManifestError("manifest exceeds size limit")
    try:
        payload = _parse_json_strict(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        raise ManifestError("manifest JSON is invalid") from exc
    return validate_manifest(payload, product=config.product, channel=channel, allowlisted_hosts=config.allowlisted_hosts, supported_platform=config.supported_platform, now=now, max_clock_skew_seconds=config.max_clock_skew_seconds)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(64 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _copy_verified_wheel(source: Path, destination: Path, manifest: ReleaseManifest, limit: int) -> None:
    _secure_existing(source, root_owner=(os.geteuid() == 0))
    if source.stat().st_size > limit:
        raise IntegrityError("wheel exceeds size limit")
    if source.stat().st_size != manifest.wheel_size or _sha256(source) != manifest.wheel_sha256:
        raise IntegrityError("wheel failed manifest verification")
    if destination.exists() or destination.is_symlink():
        raise IntegrityError("staging wheel destination already exists")
    source_fd = _open_nofollow(source, os.O_RDONLY)
    destination_fd = _open_nofollow(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o640)
    try:
        with os.fdopen(source_fd, "rb") as source_stream, os.fdopen(destination_fd, "wb") as destination_stream:
            shutil.copyfileobj(source_stream, destination_stream, length=64 * 1024)
            destination_stream.flush()
            os.fsync(destination_stream.fileno())
    except Exception:
        with contextlib.suppress(FileNotFoundError):
            destination.unlink()
        raise


def _state_after_activation(
    before: UpdateState,
    manifest: ReleaseManifest,
    final: Path,
    old: Path | None,
    now: _datetime.datetime,
    *,
    outcome: str = "activated",
) -> UpdateState:
    entries = [
        {"name": final.name, "version": manifest.version, "sequence": manifest.sequence, "channel": manifest.channel},
        *before.releases,
    ]
    if old is not None and not any(item.get("name") == old.name for item in entries):
        entries.append({"name": old.name, "version": before.active_version, "sequence": before.active_sequence, "channel": before.active_channel})
    floors = dict(before.channel_sequences)
    floors[manifest.channel] = max(floors.get(manifest.channel, -1), manifest.sequence)
    return UpdateState(
        manifest.version, manifest.sequence, manifest.channel, tuple(entries), outcome, None,
        now.isoformat(), tuple(sorted(floors.items())),
    )


def _state_after_failure(
    before: UpdateState,
    outcome: str,
    error: str,
    now: _datetime.datetime,
    *,
    channel_sequences: tuple[tuple[str, int], ...] | None = None,
) -> UpdateState:
    return UpdateState(
        before.active_version, before.active_sequence, before.active_channel, before.releases,
        outcome, error[:1000], now.isoformat(), channel_sequences or before.channel_sequences,
    )


def _prune_releases(root: Path, retain: int, keep: set[Path]) -> None:
    if isinstance(retain, bool) or not isinstance(retain, int) or retain < 0:
        raise ValueError("retain must be a non-negative integer")
    def sequence(item: Path) -> int:
        """Return sequence."""
        match = re.match(r"(\d+)-", item.name)
        return int(match.group(1)) if match else -1
    candidates = sorted(
        (item for item in root.iterdir() if item.is_dir() and not item.is_symlink()),
        key=lambda item: (sequence(item), item.name), reverse=True,
    )
    kept = 0
    for item in candidates:
        if item in keep or item.name.startswith("legacy-"):
            continue
        if kept < max(0, retain):
            kept += 1
            continue
        shutil.rmtree(item)


# Friendly functional API for adapters that do not need to retain an Updater instance.
def status(*, config: UpdaterConfig | None = None) -> UpdateState:
    """Return status."""
    return Updater(config).status()


def check(channel: str = "stable", *, config: UpdaterConfig | None = None, **kwargs: Any) -> CheckResult:
    """Check."""
    return Updater(config).check(channel, **kwargs)


def apply(channel: str = "stable", *, config: UpdaterConfig | None = None, **kwargs: Any) -> UpdateResult:
    """Apply changes."""
    return Updater(config).apply(channel, **kwargs)


def rollback(version: str | None = None, *, config: UpdaterConfig | None = None) -> UpdateResult:
    """Rollback changes."""
    return Updater(config).rollback(version)


# Naming aliases keep the low-level seams convenient for tests and future
# adapters without exposing any alternate, less-safe update path.
verify_manifest = verify_manifest_signature
parse_manifest = validate_manifest
download_wheel = stream_download


__all__ = [
    "ActivationError", "BusyError", "CheckResult", "DownloadError", "IntegrityError", "ManifestError",
    "ReleaseManifest", "RollbackError", "SignatureError", "SignatureResult", "StagingError", "UpdateExitCode",
    "UpdateResult", "UpdateState", "Updater", "UpdaterConfig", "UpdaterError", "apply", "atomic_write_json",
    "check", "download_wheel", "load_signed_manifest", "migrate_legacy_install", "parse_manifest",
    "read_state", "rollback", "status", "stream_download", "validate_manifest", "verify_manifest",
    "verify_manifest_signature",
]
