#!/usr/bin/env python3
"""Generate and validate Secure CLI Updater V1 release manifests.

The manifest is deliberately small and strict.  JSON is emitted with sorted
keys, compact separators, and one trailing LF; the exact resulting bytes are
the bytes signed by the release workflow.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import re
import sys
from email.parser import BytesParser
from email.policy import compat32
from typing import Any
from urllib.parse import quote, urlsplit
import zipfile


SCHEMA = 1
PRODUCT = "wpfy"
CHANNELS = frozenset({"stable", "rc"})
CHANNEL_MANIFEST_NAME = "manifest.json"
CHANNEL_SIGNATURE_NAME = "manifest.json.asc"
_VERSION_RE = re.compile(r"^(?P<base>\d+\.\d+\.\d+)(?:(?P<pre>a|b|rc)(?P<number>\d+))?$")
_TAG_RE = re.compile(r"^v(?P<base>\d+\.\d+\.\d+)(?:-(?P<pre>a|b|rc)(?P<number>\d+))?$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_ISO_UTC_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
_WHEEL_RE = re.compile(
    r"^(?P<distribution>[^-]+)-(?P<version>[^-]+)-(?P<python>[^-]+)-"
    r"(?P<abi>[^-]+)-(?P<platform>[^.]+)\.whl$"
)

_TOP_LEVEL_KEYS = frozenset(
    {"schema", "product", "channel", "sequence", "generated_at", "expires_at", "release", "artifact"}
)
_RELEASE_KEYS = frozenset({"version", "prerelease", "tag", "platform"})
_PLATFORM_KEYS = frozenset({"python", "abi", "platform"})
_ARTIFACT_KEYS = frozenset({"name", "url", "size", "sha256"})


class ManifestError(ValueError):
    """Raised when release input or manifest data violates V1 rules."""


@dataclass(frozen=True)
class WheelMetadata:
    name: str
    version: str
    python_tag: str
    abi_tag: str
    platform_tag: str

    @property
    def platform(self) -> dict[str, str]:
        return {
            "python": self.python_tag,
            "abi": self.abi_tag,
            "platform": self.platform_tag,
        }


def _require_exact_keys(value: Any, expected: frozenset[str], label: str) -> None:
    if not isinstance(value, dict):
        raise ManifestError(f"{label} must be an object")
    actual = frozenset(value)
    if actual != expected:
        missing = ", ".join(sorted(expected - actual))
        extra = ", ".join(sorted(actual - expected))
        details = []
        if missing:
            details.append(f"missing: {missing}")
        if extra:
            details.append(f"unexpected: {extra}")
        raise ManifestError(f"{label} has invalid keys ({'; '.join(details)})")


def _version_parts(version: str) -> tuple[str, str | None, int | None]:
    if not isinstance(version, str) or not version:
        raise ManifestError("release.version must be a non-empty string")
    match = _VERSION_RE.fullmatch(version)
    if match is None:
        raise ManifestError(f"unsupported package version: {version!r}")
    pre = match.group("pre")
    number = int(match.group("number")) if pre else None
    return match.group("base"), pre, number


def canonical_tag(version: str) -> str:
    """Return V1's public tag spelling for a package version."""
    base, pre, number = _version_parts(version)
    return f"v{base}" if pre is None else f"v{base}-{pre}{number}"


def channel_asset_urls(repository: str, channel: str) -> tuple[str, str]:
    """Return client-compatible signed channel asset URLs."""
    if not isinstance(repository, str) or re.fullmatch(r"[^/\s]+/[^/\s]+", repository) is None:
        raise ManifestError("repository must be owner/repository")
    if type(channel) is not str or channel not in CHANNELS:
        raise ManifestError("channel must be 'stable' or 'rc'")
    base = f"https://github.com/{repository}/releases/download/{channel}"
    return f"{base}/{CHANNEL_MANIFEST_NAME}", f"{base}/{CHANNEL_SIGNATURE_NAME}"


def _parse_tag(tag: str) -> tuple[str, str | None, int | None]:
    if not isinstance(tag, str) or not tag:
        raise ManifestError("tag/ref is required")
    match = _TAG_RE.fullmatch(tag)
    if match is None:
        raise ManifestError(f"tag must be a canonical V1 tag (got {tag!r})")
    pre = match.group("pre")
    return match.group("base"), pre, int(match.group("number")) if pre else None


def _is_prerelease(version: str) -> bool:
    return _version_parts(version)[1] is not None


def _parse_timestamp(value: Any, field: str) -> datetime:
    if not isinstance(value, str) or _ISO_UTC_RE.fullmatch(value) is None:
        raise ManifestError(f"{field} must be UTC timestamp in YYYY-MM-DDTHH:MM:SSZ form")
    parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    return parsed


def _utc_timestamp(value: datetime) -> str:
    if value.tzinfo is None:
        raise ManifestError("timestamp must include a timezone")
    return value.astimezone(timezone.utc).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_json_no_duplicates(text: str) -> Any:
    def pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ManifestError(f"duplicate JSON key: {key}")
            result[key] = value
        return result

    def invalid_constant(value: str) -> Any:
        raise ManifestError(f"invalid JSON constant: {value}")

    try:
        return json.loads(text, object_pairs_hook=pairs, parse_constant=invalid_constant)
    except json.JSONDecodeError as exc:
        raise ManifestError(f"invalid manifest JSON: {exc}") from exc


def load_manifest(path: Path) -> dict[str, Any]:
    value = _parse_json_no_duplicates(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ManifestError("manifest root must be an object")
    return value


def manifest_bytes(manifest: dict[str, Any]) -> bytes:
    """Serialize manifest exactly as release workflow signs it."""
    return (json.dumps(manifest, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def _sha256_and_size(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
            size += len(chunk)
    if size < 1:
        raise ManifestError("wheel must not be empty")
    return digest.hexdigest(), size


def _header_value(message: Any, name: str) -> str:
    value = message.get(name)
    if not isinstance(value, str) or not value.strip():
        raise ManifestError(f"wheel METADATA has no {name} value")
    return value.strip()


def read_wheel_metadata(path: Path) -> WheelMetadata:
    """Read package identity and wheel tags without installing the wheel."""
    match = _WHEEL_RE.fullmatch(path.name)
    if match is None:
        raise ManifestError(f"not a supported wheel filename: {path.name!r}")

    metadata_members: list[str] = []
    wheel_members: list[str] = []
    try:
        with zipfile.ZipFile(path) as archive:
            for member in archive.namelist():
                if member.endswith(".dist-info/METADATA"):
                    metadata_members.append(member)
                elif member.endswith(".dist-info/WHEEL"):
                    wheel_members.append(member)
            if len(metadata_members) != 1 or len(wheel_members) != 1:
                raise ManifestError("wheel must contain exactly one METADATA and one WHEEL file")
            metadata = BytesParser(policy=compat32).parsebytes(archive.read(metadata_members[0]))
            wheel_info = BytesParser(policy=compat32).parsebytes(archive.read(wheel_members[0]))
    except (OSError, zipfile.BadZipFile) as exc:
        raise ManifestError(f"cannot read wheel: {exc}") from exc

    name = _header_value(metadata, "Name")
    version = _header_value(metadata, "Version")
    _version_parts(version)
    if re.sub(r"[-_.]+", "-", name).lower() != PRODUCT:
        raise ManifestError(f"wheel package must be {PRODUCT!r}, got {name!r}")
    if match.group("distribution").replace("_", "-").lower() != PRODUCT:
        raise ManifestError(f"wheel filename distribution must be {PRODUCT!r}")
    if match.group("version").replace("_", ".") != version:
        raise ManifestError("wheel filename version does not match METADATA version")
    if not wheel_info.get("Wheel-Version"):
        raise ManifestError("wheel metadata has no Wheel-Version")
    filename_tag = f"{match.group('python')}-{match.group('abi')}-{match.group('platform')}"
    if filename_tag not in (wheel_info.get_all("Tag") or []):
        raise ManifestError("wheel filename platform tags do not match WHEEL metadata")
    return WheelMetadata(
        name=PRODUCT,
        version=version,
        python_tag=match.group("python"),
        abi_tag=match.group("abi"),
        platform_tag=match.group("platform"),
    )


def _validate_platform(value: Any) -> None:
    _require_exact_keys(value, _PLATFORM_KEYS, "release.platform")
    for key, item in value.items():
        if not isinstance(item, str) or not item or any(char.isspace() for char in item):
            raise ManifestError(f"release.platform.{key} must be a non-empty token")


def validate_manifest(
    manifest: dict[str, Any],
    *,
    wheel_path: Path | None = None,
    expected_channel: str | None = None,
    expected_tag: str | None = None,
    expected_sequence: int | None = None,
    expected_base_url: str | None = None,
    previous_manifest: dict[str, Any] | None = None,
    require_unexpired: bool = False,
) -> dict[str, Any]:
    """Validate V1 manifest and, when supplied, its actual wheel evidence."""
    _require_exact_keys(manifest, _TOP_LEVEL_KEYS, "manifest")
    if manifest["schema"] != SCHEMA or type(manifest["schema"]) is not int:
        raise ManifestError(f"manifest.schema must be integer {SCHEMA}")
    if manifest["product"] != PRODUCT:
        raise ManifestError(f"manifest.product must be {PRODUCT!r}")
    channel = manifest["channel"]
    if type(channel) is not str or channel not in CHANNELS:
        raise ManifestError("manifest.channel must be 'stable' or 'rc'")
    if expected_channel is not None and channel != expected_channel:
        raise ManifestError("manifest.channel does not match expected channel")
    sequence = manifest["sequence"]
    if type(sequence) is not int or sequence < 1:
        raise ManifestError("manifest.sequence must be positive integer")
    if expected_sequence is not None and sequence != expected_sequence:
        raise ManifestError("manifest.sequence does not match expected sequence")

    generated = _parse_timestamp(manifest["generated_at"], "manifest.generated_at")
    expires = _parse_timestamp(manifest["expires_at"], "manifest.expires_at")
    if expires <= generated:
        raise ManifestError("manifest.expires_at must be later than generated_at")
    if require_unexpired and expires <= datetime.now(timezone.utc):
        raise ManifestError("manifest.expires_at is in the past")

    release = manifest["release"]
    _require_exact_keys(release, _RELEASE_KEYS, "manifest.release")
    version = release["version"]
    base, pre, number = _version_parts(version)
    prerelease = release["prerelease"]
    if type(prerelease) is not bool or prerelease != (pre is not None):
        raise ManifestError("release.prerelease does not match release.version")
    tag = release["tag"]
    tag_base, tag_pre, tag_number = _parse_tag(tag)
    if (base, pre, number) != (tag_base, tag_pre, tag_number) or canonical_tag(version) != tag:
        raise ManifestError("release.tag does not match release.version")
    if expected_tag is not None and tag != expected_tag:
        raise ManifestError("release.tag does not match expected tag/ref")
    if channel == "stable" and prerelease:
        raise ManifestError("stable channel cannot contain prerelease version")
    if channel == "rc" and not prerelease:
        raise ManifestError("rc channel requires prerelease version")
    _validate_platform(release["platform"])

    artifact = manifest["artifact"]
    _require_exact_keys(artifact, _ARTIFACT_KEYS, "manifest.artifact")
    name = artifact["name"]
    if not isinstance(name, str) or not name or Path(name).name != name or not name.endswith(".whl"):
        raise ManifestError("artifact.name must be wheel basename")
    url = artifact["url"]
    if not isinstance(url, str):
        raise ManifestError("artifact.url must be string")
    parsed_url = urlsplit(url)
    if parsed_url.scheme != "https" or not parsed_url.netloc or parsed_url.query or parsed_url.fragment:
        raise ManifestError("artifact.url must be HTTPS URL without query or fragment")
    if parsed_url.path.rstrip("/").split("/")[-1] != name:
        raise ManifestError("artifact.url basename must match artifact.name")
    size = artifact["size"]
    if type(size) is not int or size < 1:
        raise ManifestError("artifact.size must be positive integer")
    digest = artifact["sha256"]
    if not isinstance(digest, str) or _SHA256_RE.fullmatch(digest) is None:
        raise ManifestError("artifact.sha256 must be lowercase SHA-256")
    if expected_base_url is not None:
        base_url = expected_base_url.rstrip("/")
        expected_url = f"{base_url}/{quote(tag, safe='')}/{quote(name, safe='')}"
        if url != expected_url:
            raise ManifestError("artifact.url does not match expected release base URL")

    if previous_manifest is not None:
        _require_exact_keys(previous_manifest, _TOP_LEVEL_KEYS, "previous manifest")
        previous_sequence = previous_manifest["sequence"]
        if type(previous_sequence) is not int or sequence <= previous_sequence:
            raise ManifestError("manifest.sequence must be greater than previous manifest sequence")

    if wheel_path is not None:
        wheel = Path(wheel_path)
        wheel_metadata = read_wheel_metadata(wheel)
        wheel_digest, wheel_size = _sha256_and_size(wheel)
        if name != wheel.name or version != wheel_metadata.version or release["platform"] != wheel_metadata.platform:
            raise ManifestError("manifest release identity does not match wheel metadata")
        if size != wheel_size or digest != wheel_digest:
            raise ManifestError("manifest artifact size or SHA-256 does not match wheel")
    return manifest


def build_manifest(
    wheel_path: Path,
    *,
    tag: str,
    channel: str,
    sequence: int,
    base_url: str,
    generated_at: datetime | None = None,
    expires_at: datetime | None = None,
    expires_in_days: int = 30,
    previous_manifest: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build, validate, and return a deterministic V1 manifest object."""
    wheel = Path(wheel_path)
    metadata = read_wheel_metadata(wheel)
    if not isinstance(tag, str) or not tag:
        raise ManifestError("tag/ref is required")
    _parse_tag(tag)
    if type(channel) is not str or channel not in CHANNELS:
        raise ManifestError("channel must be 'stable' or 'rc'")
    if type(sequence) is not int or sequence < 1:
        raise ManifestError("sequence must be positive integer")
    if not isinstance(base_url, str) or not base_url:
        raise ManifestError("base URL is required")
    base_parts = urlsplit(base_url)
    if base_parts.scheme != "https" or not base_parts.netloc or base_parts.query or base_parts.fragment:
        raise ManifestError("base URL must be HTTPS URL without query or fragment")
    generated = generated_at or datetime.now(timezone.utc)
    if expires_at is None:
        if type(expires_in_days) is not int or expires_in_days < 1:
            raise ManifestError("expires-in-days must be positive integer")
        expires_at = generated + timedelta(days=expires_in_days)
    digest, size = _sha256_and_size(wheel)
    manifest = {
        "schema": SCHEMA,
        "product": PRODUCT,
        "channel": channel,
        "sequence": sequence,
        "generated_at": _utc_timestamp(generated),
        "expires_at": _utc_timestamp(expires_at),
        "release": {
            "version": metadata.version,
            "prerelease": _is_prerelease(metadata.version),
            "tag": tag,
            "platform": metadata.platform,
        },
        "artifact": {
            "name": wheel.name,
            "url": f"{base_url.rstrip('/')}/{quote(tag, safe='')}/{quote(wheel.name, safe='')}",
            "size": size,
            "sha256": digest,
        },
    }
    return validate_manifest(
        manifest,
        wheel_path=wheel,
        expected_channel=channel,
        expected_tag=tag,
        expected_base_url=base_url,
        previous_manifest=previous_manifest,
    )


def _positive_int(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be integer") from exc
    if parsed < 1:
        raise argparse.ArgumentTypeError("must be at least 1")
    return parsed


def _timestamp(value: str) -> datetime:
    try:
        return _parse_timestamp(value, "timestamp")
    except ManifestError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc


def _previous(path: str | None) -> dict[str, Any] | None:
    return load_manifest(Path(path)) if path else None


def _generate(args: argparse.Namespace) -> int:
    manifest = build_manifest(
        Path(args.wheel),
        tag=args.tag,
        channel=args.channel,
        sequence=args.sequence,
        base_url=args.base_url,
        generated_at=args.generated_at,
        expires_at=args.expires_at,
        expires_in_days=args.expires_in_days,
        previous_manifest=_previous(args.previous_manifest),
    )
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(manifest_bytes(manifest))
    return 0


def _validate(args: argparse.Namespace) -> int:
    manifest = load_manifest(Path(args.manifest))
    validate_manifest(
        manifest,
        wheel_path=Path(args.wheel) if args.wheel else None,
        expected_channel=args.channel,
        expected_tag=args.tag,
        expected_sequence=args.sequence,
        expected_base_url=args.base_url,
        previous_manifest=_previous(args.previous_manifest),
        require_unexpired=args.require_unexpired,
    )
    print("release manifest valid")
    return 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)

    generate = commands.add_parser("generate", help="generate and validate manifest")
    generate.add_argument("--wheel", required=True, type=Path)
    generate.add_argument("--tag", required=True)
    generate.add_argument("--channel", required=True, choices=sorted(CHANNELS))
    generate.add_argument("--sequence", required=True, type=_positive_int)
    generate.add_argument("--base-url", required=True)
    generate.add_argument("--output", required=True, type=Path)
    generate.add_argument("--generated-at", type=_timestamp)
    generate.add_argument("--expires-at", type=_timestamp)
    generate.add_argument("--expires-in-days", type=_positive_int, default=30)
    generate.add_argument("--previous-manifest", type=Path)
    generate.set_defaults(handler=_generate)

    validate = commands.add_parser("validate", help="strictly validate manifest and optional wheel")
    validate.add_argument("--manifest", required=True, type=Path)
    validate.add_argument("--wheel", type=Path)
    validate.add_argument("--tag")
    validate.add_argument("--channel", choices=sorted(CHANNELS))
    validate.add_argument("--sequence", type=_positive_int)
    validate.add_argument("--base-url")
    validate.add_argument("--previous-manifest", type=Path)
    validate.add_argument("--require-unexpired", action="store_true")
    validate.set_defaults(handler=_validate)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    try:
        return args.handler(args)
    except (ManifestError, OSError, zipfile.BadZipFile) as exc:
        parser.error(str(exc))
    return 2


if __name__ == "__main__":
    sys.exit(main())
