"""WPFY Login Shield: pinned wp-fail2ban plugin install and ownership.

Task t06. Installs the official WordPress.org plugin (slug ``wp-fail2ban``,
project ``wp-fail2ban/wp-fail2ban``) pinned to 5.4.1-LTS into a single site
through the existing WP-CLI runner, and records per-site ownership so a later
disable can never uninstall or deactivate an administrator-owned plugin.

Integrity is checked before any install: the version-pinned WordPress.org
plugin-checksums JSON is fetched and every archive file (plus the zip itself)
is verified against the published md5 and sha256 hashes. When the integrity
path is unavailable the decision is recorded as an explicit no-evidence risk in
the WPFY-owned manifest instead of installing silently.

No host Fail2ban jail activation happens here; this module only installs and
owns the WordPress plugin.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import urllib.request
import zipfile

from .events import record_event
from .site_paths import site_dir, site_exists, validate_domain
from .site_runtime import run_wp_cli
from .site_security import (
    WPFY_PLUGIN_OWNERSHIP,
    load_security,
    save_security,
)

# ---------------------------------------------------------------------------
# Pinned plugin metadata (t03 research: version-pinned checksums, GPLv3 terms)
# ---------------------------------------------------------------------------

WP_FAIL2BAN_SLUG = "wp-fail2ban"
WP_FAIL2BAN_VERSION = "5.4.1"
WP_FAIL2BAN_ZIP_URL = (
    f"https://downloads.wordpress.org/plugin/{WP_FAIL2BAN_SLUG}.{WP_FAIL2BAN_VERSION}.zip"
)
WP_FAIL2BAN_CHECKSUM_URL = (
    "https://downloads.wordpress.org/plugin-checksums/"
    f"{WP_FAIL2BAN_SLUG}/{WP_FAIL2BAN_VERSION}.json"
)
WP_FAIL2BAN_LICENSE = "GPLv3 (with GPLv3 Section 7 attribution terms)"
WP_FAIL2BAN_REQUIRES_PHP = "7.4"
WP_FAIL2BAN_TESTED_UP_TO = "6.8.6"
WP_FAIL2BAN_INTEGRITY_METHOD = (
    "WordPress.org plugin-checksums JSON: per-file md5+sha256 verified after "
    "download, plus zip-level sha256"
)
WP_FAIL2BAN_INTEGRITY_RESIDUAL_RISK = (
    "Checksum list is signed by WordPress.org trust only (HTTPS); there is no "
    "independent maintainer PGP signature for plugin zips."
)

# Staging inside the per-site security directory, mounted read-only into the
# wpcli service as /security (see site_layout.py wpcli volumes). The verified
# archive never lives inside the WordPress document root.
STAGING_SUBDIR = "security"

_FETCH_TIMEOUT = 60
_DOWNLOAD_TIMEOUT = 300
_ZIP_CHUNK = 1024 * 1024


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class IntegrityResult:
    verified: bool
    errors: tuple[str, ...] = ()
    file_count: int = 0
    zip_sha256: str | None = None
    checksum_manifest: dict | None = None
    risk: str | None = None


@dataclass(frozen=True, slots=True)
class PluginInstallResult:
    exit_code: int
    message: str
    changed: bool = False
    skipped: bool = False
    ownership: str | None = None
    integrity_verified: bool = False
    integrity_risk: str | None = None


@dataclass(frozen=True, slots=True)
class _PluginState:
    available: bool
    status: str = ""
    version: str = ""


# ---------------------------------------------------------------------------
# Path helpers
# ---------------------------------------------------------------------------


def _current_paths():
    from .settings import PATHS as current_paths

    return current_paths


def plugin_manifest_path() -> Path:
    """WPFY-owned manifest recording the pinned version and integrity evidence."""
    return Path(_current_paths().state_dir) / "login-shield" / "plugin-manifest.json"


def plugin_staging_dir(domain: str) -> Path:
    validate_domain(domain)
    return site_dir(domain) / STAGING_SUBDIR


def load_plugin_manifest() -> dict | None:
    try:
        return json.loads(plugin_manifest_path().read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def _build_manifest(
    *,
    verified: bool,
    risk: str | None = None,
    checksums: dict | None = None,
    zip_sha256: str | None = None,
    file_count: int = 0,
) -> dict:
    payload = {
        "slug": WP_FAIL2BAN_SLUG,
        "version": WP_FAIL2BAN_VERSION,
        "zip_url": WP_FAIL2BAN_ZIP_URL,
        "checksum_url": WP_FAIL2BAN_CHECKSUM_URL,
        "license": WP_FAIL2BAN_LICENSE,
        "requires_php": WP_FAIL2BAN_REQUIRES_PHP,
        "tested_up_to": WP_FAIL2BAN_TESTED_UP_TO,
        "integrity_method": WP_FAIL2BAN_INTEGRITY_METHOD,
        "residual_risk": WP_FAIL2BAN_INTEGRITY_RESIDUAL_RISK,
        "verified": verified,
    }
    if risk:
        payload["risk"] = risk
    if zip_sha256:
        payload["zip_sha256"] = zip_sha256
    if file_count:
        payload["file_count"] = file_count
    if checksums:
        payload["checksums"] = checksums
    return payload


def _write_plugin_manifest(payload: dict) -> Path:
    from .site_security import _install_text

    path = plugin_manifest_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    content = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    _install_text(path.parent, path.name, content, 0o600)
    return path


# ---------------------------------------------------------------------------
# Integrity helpers
# ---------------------------------------------------------------------------


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(_ZIP_CHUNK), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _normalize_member_name(name: str) -> str:
    name = name.replace("\\", "/")
    while name.startswith("/") or name.startswith("./"):
        name = name[1:] if name.startswith("/") else name[2:]
    return name


def _common_plugin_prefix(names: list[str]) -> str:
    prefix = f"{WP_FAIL2BAN_SLUG}/"
    return prefix if names and all(name.startswith(prefix) for name in names) else ""


def _expected_hash_values(value: object, *, field: str, relative: str) -> tuple[str, ...]:
    """Normalize a per-file checksum value into the acceptable hashes.

    WordPress.org plugin-checksums JSON emits each md5/sha256 either as a
    single hash string or as an ARRAY of acceptable hash strings (repack
    detection, wp-fail2ban 5.4.1). Any other shape is schema drift and fails
    closed so the caller refuses the archive instead of mis-verifying.
    """
    if isinstance(value, str):
        return (value,)
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return tuple(value)
    raise ValueError(
        f"{relative}: malformed {field} value in checksum manifest "
        "(expected hash string or list of hash strings)"
    )


def fetch_checksum_manifest(
    url: str = WP_FAIL2BAN_CHECKSUM_URL, *, timeout: float = _FETCH_TIMEOUT
) -> IntegrityResult:
    """Fetch the version-pinned WordPress.org checksum JSON (offline-safe)."""
    try:
        with urllib.request.urlopen(url, timeout=timeout) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except (OSError, ValueError) as exc:
        return IntegrityResult(False, risk=f"checksum manifest fetch failed: {exc}")
    if not isinstance(payload, dict):
        return IntegrityResult(False, risk="checksum manifest is not a JSON object")
    files = payload.get("files")
    if not isinstance(files, dict) or not files:
        return IntegrityResult(False, risk="checksum manifest has no per-file hashes")
    return IntegrityResult(True, checksum_manifest=payload)


def download_plugin_zip(
    dest_dir: Path, *, url: str = WP_FAIL2BAN_ZIP_URL, timeout: float = _DOWNLOAD_TIMEOUT
) -> Path:
    """Download the pinned plugin zip into dest_dir; atomic rename on success."""
    dest_dir.mkdir(parents=True, exist_ok=True)
    target = dest_dir / f"{WP_FAIL2BAN_SLUG}-{WP_FAIL2BAN_VERSION}.zip"
    with urllib.request.urlopen(url, timeout=timeout) as response:
        data = response.read()
    temporary = target.with_name(f".{target.name}.{os.getpid()}.tmp")
    temporary.write_bytes(data)
    os.replace(temporary, target)
    return target


def verify_plugin_zip(zip_path: Path, checksum_manifest: dict) -> IntegrityResult:
    """Verify every archive member and the zip itself against the checksum JSON."""
    files = checksum_manifest.get("files")
    if not isinstance(files, dict) or not files:
        return IntegrityResult(False, errors=("checksum manifest has no per-file hashes",))
    errors: list[str] = []
    zip_sha256: str | None = None
    zip_entry = checksum_manifest.get("zip")
    if isinstance(zip_entry, dict):
        expected_zip = zip_entry.get(WP_FAIL2BAN_ZIP_URL)
        if isinstance(expected_zip, dict) and expected_zip.get("sha256"):
            zip_sha256 = _sha256_file(zip_path)
            if zip_sha256 != expected_zip["sha256"]:
                errors.append("zip sha256 does not match the WordPress.org checksum manifest")
    try:
        archive = zipfile.ZipFile(zip_path)
    except (OSError, zipfile.BadZipFile) as exc:
        return IntegrityResult(False, errors=(f"plugin archive is not a valid zip: {exc}",))
    seen: set[str] = set()
    with archive:
        members = [info for info in archive.infolist() if not info.is_dir()]
        names = [_normalize_member_name(info.filename) for info in members]
        prefix = _common_plugin_prefix(names)
        for info, name in zip(members, names):
            relative = name[len(prefix):] if prefix else name
            if relative in seen:
                continue
            seen.add(relative)
            entry = files.get(relative)
            if entry is None:
                errors.append(f"unexpected file in archive: {relative}")
                continue
            data = archive.read(info)
            if not isinstance(entry, dict):
                errors.append(f"malformed checksum entry for {relative}")
                continue
            for field, digest in (("md5", hashlib.md5), ("sha256", hashlib.sha256)):
                raw = entry.get(field)
                if not raw:
                    continue
                try:
                    expected = _expected_hash_values(raw, field=field, relative=relative)
                except ValueError as exc:
                    errors.append(str(exc))
                    continue
                if digest(data).hexdigest() not in expected:
                    errors.append(f"{field} mismatch for {relative}")
        missing = sorted(set(files) - seen)
        if missing:
            shown = ", ".join(missing[:5])
            errors.append(f"missing files from archive: {shown}{'...' if len(missing) > 5 else ''}")
    if errors:
        return IntegrityResult(False, errors=tuple(errors), file_count=len(files), zip_sha256=zip_sha256)
    return IntegrityResult(
        True,
        file_count=len(files),
        zip_sha256=zip_sha256,
        checksum_manifest=checksum_manifest,
    )


# ---------------------------------------------------------------------------
# WP-CLI interaction
# ---------------------------------------------------------------------------


def _read_plugin_state(domain: str) -> _PluginState:
    status_result = run_wp_cli(domain, "plugin", "get", WP_FAIL2BAN_SLUG, "--field=status")
    if status_result.skipped:
        return _PluginState(available=False)
    if status_result.exit_code != 0:
        # wp plugin get fails when the plugin is not installed.
        return _PluginState(available=True, status="")
    active = status_result.stdout.strip() == "active"
    version_result = run_wp_cli(domain, "plugin", "get", WP_FAIL2BAN_SLUG, "--field=version")
    version = version_result.stdout.strip() if version_result.exit_code == 0 else ""
    return _PluginState(available=True, status="active" if active else "inactive", version=version)


def plugin_live_state(domain: str) -> dict | None:
    """Live wp-fail2ban plugin state via wp-cli; None when it cannot be read.

    Returns ``{"active": bool, "version": str}`` when the runtime is
    available and the plugin is installed. ``None`` when the runtime is
    skipped/unavailable or the plugin is not installed, so callers fall back
    to the recorded flag (t16 W8: an out-of-band deactivation must never be
    reported as active; under runtime skip the recorded value is the bounded
    staleness contract).
    """
    validate_domain(domain)
    state = _read_plugin_state(domain)
    if not state.available or not state.status:
        return None
    return {"active": state.status == "active", "version": state.version}


def _refresh_site_compose(domain: str) -> None:
    from .site_definition import SiteDefinition
    from .site_layout import ensure_site_scaffold
    from .site_paths import env_path, read_env

    definition = SiteDefinition.from_env(domain, read_env(env_path(domain)))
    ensure_site_scaffold(definition)


def _record_plugin_state(domain: str, *, ownership: str, version: str, auto_updates_disabled: bool) -> dict:
    config = load_security(domain)
    desired = {
        "slug": WP_FAIL2BAN_SLUG,
        "version": version,
        "ownership": ownership,
        "auto_updates_disabled": auto_updates_disabled,
        "active": True,
    }
    existing = config.get("fail2ban_plugin") or {}
    if existing != desired:
        updated = dict(config)
        updated["fail2ban_plugin"] = desired
        save_security(domain, updated)
        return desired
    return existing


# ---------------------------------------------------------------------------
# Install / deactivate operations
# ---------------------------------------------------------------------------


def install_wp_fail2ban(domain: str) -> PluginInstallResult:
    """Ensure the pinned official plugin is installed and active in one site.

    Integrity is verified before any install. When the integrity path is
    unavailable the no-evidence decision is written to the manifest and the
    install is refused. Administrator-installed and already-active copies are
    never overwritten; their ownership is recorded instead.
    """
    validate_domain(domain)
    if not site_exists(domain):
        return PluginInstallResult(3, f"site not found: {domain}")

    state = _read_plugin_state(domain)
    if not state.available:
        return PluginInstallResult(
            0, "wp-fail2ban plugin install skipped (runtime unavailable)", skipped=True
        )

    config = load_security(domain)
    existing = config.get("fail2ban_plugin") or {}
    recorded_ownership = existing.get("ownership")
    ownership = None
    changed = False
    integrity_verified = False

    if not state.status:
        # Integrity first: verify the pinned archive before any install.
        integrity = fetch_checksum_manifest()
        if not integrity.verified:
            _write_plugin_manifest(_build_manifest(verified=False, risk=integrity.risk))
            return PluginInstallResult(
                3,
                f"wp-fail2ban install refused without integrity evidence: {integrity.risk}",
                integrity_risk=integrity.risk,
            )
        try:
            zip_path = download_plugin_zip(plugin_staging_dir(domain))
        except (OSError, ValueError) as exc:
            risk = f"plugin zip download failed: {exc}"
            _write_plugin_manifest(_build_manifest(verified=False, risk=risk))
            return PluginInstallResult(3, f"wp-fail2ban install refused: {risk}", integrity_risk=risk)
        verified = verify_plugin_zip(zip_path, integrity.checksum_manifest)
        if not verified.verified:
            risk = "; ".join(verified.errors)
            _write_plugin_manifest(_build_manifest(verified=False, risk=risk))
            return PluginInstallResult(3, f"wp-fail2ban install refused: {risk}", integrity_risk=risk)
        _write_plugin_manifest(
            _build_manifest(
                verified=True,
                checksums=integrity.checksum_manifest,
                zip_sha256=verified.zip_sha256,
                file_count=verified.file_count,
            )
        )
        integrity_verified = True
        _refresh_site_compose(domain)
        installed = run_wp_cli(domain, "plugin", "install", f"/security/{zip_path.name}")
        if installed.exit_code != 0:
            return PluginInstallResult(
                3,
                f"wp plugin install failed: {installed.stderr.strip() or installed.stdout.strip()}",
            )
        changed = True
        ownership = "wpfy-installed"
    elif recorded_ownership:
        ownership = recorded_ownership
    elif state.status == "active":
        ownership = "already-active"
    else:
        ownership = "admin-installed"

    if state.status != "active":
        activated = run_wp_cli(domain, "plugin", "activate", WP_FAIL2BAN_SLUG)
        if activated.exit_code != 0:
            return PluginInstallResult(
                3,
                f"wp plugin activate failed: {activated.stderr.strip() or activated.stdout.strip()}",
            )
        changed = True
        if ownership in (None, "admin-installed"):
            ownership = "activated-by-wpfy"

    auto_updates_disabled = bool(existing.get("auto_updates_disabled"))
    if ownership in WPFY_PLUGIN_OWNERSHIP and not auto_updates_disabled:
        auto_result = run_wp_cli(domain, "plugin", "auto-updates", "disable", WP_FAIL2BAN_SLUG)
        if auto_result.exit_code == 0:
            auto_updates_disabled = True
            changed = True

    if not integrity_verified and load_plugin_manifest() is None:
        # Plugin was already present; WPFY did not verify this copy. Record the
        # no-evidence decision so t10/t24 can surface it instead of pretending.
        _write_plugin_manifest(
            _build_manifest(
                verified=False,
                risk=(
                    "plugin was already present on the site; WPFY did not install or "
                    "integrity-verify this copy"
                ),
            )
        )

    version = state.version or WP_FAIL2BAN_VERSION
    recorded = _record_plugin_state(
        domain,
        ownership=ownership,
        version=version,
        auto_updates_disabled=auto_updates_disabled,
    )
    if recorded != existing:
        changed = True

    if changed:
        record_event(
            "site.security.fail2ban-plugin.installed",
            domain=domain,
            detail=(
                f"wp-fail2ban {version} managed by wpfy (ownership={ownership}, "
                f"auto_updates_disabled={auto_updates_disabled})"
            ),
        )

    if state.status == "active" and ownership in WPFY_PLUGIN_OWNERSHIP:
        message = f"wp-fail2ban plugin active (ownership {ownership}); auto-updates disabled"
    elif state.status == "active":
        message = f"wp-fail2ban plugin already active (ownership {ownership}); admin auto-update policy preserved"
    elif state.status == "inactive":
        message = f"wp-fail2ban plugin activated (ownership {ownership})"
    else:
        message = f"wp-fail2ban {version} installed and activated (ownership {ownership})"
    if version and version != WP_FAIL2BAN_VERSION:
        message += f"; version {version} differs from WPFY-managed {WP_FAIL2BAN_VERSION}"
    return PluginInstallResult(
        0,
        message,
        changed=changed,
        ownership=ownership,
        integrity_verified=integrity_verified,
    )


def deactivate_wp_fail2ban(domain: str) -> PluginInstallResult:
    """Deactivate the plugin only when WPFY owns the activation.

    Administrator-installed and already-active plugins are preserved untouched;
    the plugin package is never uninstalled here.
    """
    validate_domain(domain)
    if not site_exists(domain):
        return PluginInstallResult(3, f"site not found: {domain}")
    config = load_security(domain)
    plugin = config.get("fail2ban_plugin") or {}
    ownership = plugin.get("ownership")
    if ownership not in WPFY_PLUGIN_OWNERSHIP:
        label = ownership or "no ownership recorded"
        return PluginInstallResult(
            0, f"wp-fail2ban plugin preserved; ownership {label}", ownership=ownership
        )
    state = _read_plugin_state(domain)
    if not state.available:
        return PluginInstallResult(
            0, "wp-fail2ban deactivate skipped (runtime unavailable)", skipped=True
        )
    if state.status != "active":
        if plugin.get("active"):
            updated = dict(config)
            updated["fail2ban_plugin"] = {**plugin, "active": False}
            save_security(domain, updated)
            record_event(
                "site.security.fail2ban-plugin.deactivated",
                domain=domain,
                detail=f"plugin already inactive; ownership {ownership}",
            )
            return PluginInstallResult(
                0, "wp-fail2ban plugin already inactive", changed=True, ownership=ownership
            )
        return PluginInstallResult(
            0, "wp-fail2ban plugin already inactive", ownership=ownership
        )
    deactivated = run_wp_cli(domain, "plugin", "deactivate", WP_FAIL2BAN_SLUG)
    if deactivated.exit_code != 0:
        return PluginInstallResult(
            3,
            f"wp plugin deactivate failed: {deactivated.stderr.strip() or deactivated.stdout.strip()}",
            ownership=ownership,
        )
    updated = dict(config)
    updated["fail2ban_plugin"] = {**plugin, "active": False}
    save_security(domain, updated)
    record_event(
        "site.security.fail2ban-plugin.deactivated",
        domain=domain,
        detail=f"wp-fail2ban deactivated; ownership {ownership}",
    )
    return PluginInstallResult(
        0, "wp-fail2ban plugin deactivated", changed=True, ownership=ownership
    )


def plugin_ownership(domain: str) -> str | None:
    """Return the recorded ownership state, or None when never recorded."""
    validate_domain(domain)
    return (load_security(domain).get("fail2ban_plugin") or {}).get("ownership")
