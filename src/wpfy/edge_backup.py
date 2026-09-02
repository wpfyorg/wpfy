"""Edge infrastructure backup and restore (Traefik, certificates, configuration)."""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile

from .s3_backup import S3ConfigError, S3Uploader, load_s3_config, redact_s3_secrets
from .settings import current_paths
from .site_runtime import RuntimeResult, docker_available, runtime_skip_requested
from . import traefik


def _edge_backup_dir() -> Path:
    return Path(current_paths().state_dir) / "backups" / "edge"


def _local_acme_path() -> Path:
    return traefik.traefik_dir() / "letsencrypt" / "acme.json"


def _copy_acme_from_container(destination: Path) -> bool:
    if runtime_skip_requested() or not docker_available():
        return False
    proc = subprocess.run(
        ["docker", "cp", f"{traefik.TRAEFIK_CONTAINER}:/letsencrypt/acme.json", str(destination)],
        check=False, capture_output=True, text=True,
    )
    return proc.returncode == 0 and destination.exists()


def backup_edge(
    *,
    destination_dir: str | Path | None = None,
    upload_s3: bool = False,
    s3_profile: str | None = None,
    uploader: S3Uploader | None = None,
) -> RuntimeResult:
    """Backup edge."""
    backup_dir = Path(destination_dir) if destination_dir is not None else _edge_backup_dir()
    backup_dir.mkdir(parents=True, exist_ok=True)
    backup_dir.chmod(0o700)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    archive_path = backup_dir / f"edge-{stamp}.tar.gz"

    with traefik.traefik_transaction():
        with tempfile.TemporaryDirectory(prefix="wpfy-edge-backup-") as temp_dir:
            root = Path(temp_dir) / "edge"
            root.mkdir()
            copied = 0
            for source, name in (
                (traefik.traefik_compose_path(), "compose.yaml"),
                (traefik.traefik_config_path(), "traefik.yml"),
            ):
                if source.exists():
                    shutil.copy2(source, root / name)
                    copied += 1
            acme = root / "letsencrypt" / "acme.json"
            acme.parent.mkdir()
            if _local_acme_path().exists():
                shutil.copy2(_local_acme_path(), acme)
                copied += 1
            elif _copy_acme_from_container(acme):
                copied += 1
            if copied == 0:
                return RuntimeResult(2, "edge state not found")
            if acme.exists():
                acme.chmod(0o600)
            with tarfile.open(archive_path, "w:gz") as archive:
                archive.add(root, arcname="edge", recursive=True)
    archive_path.chmod(0o600)

    verify = subprocess.run(["tar", "-tzf", str(archive_path)], check=False, capture_output=True, text=True)
    if verify.returncode != 0:
        err = verify.stderr.strip() or verify.stdout.strip() or "tar verification failed"
        return RuntimeResult(3, f"edge backup verification failed: {err}")

    message = f"edge backup created: {archive_path}"
    if upload_s3:
        try:
            config = load_s3_config(s3_profile)
        except S3ConfigError as exc:
            return RuntimeResult(2, f"{message}; s3 upload skipped: {exc}", ran=True)
        active_uploader = uploader or S3Uploader()
        try:
            uploaded_to = active_uploader.upload_archive(config, archive_path, "edge")
        except (OSError, S3ConfigError) as exc:
            return RuntimeResult(4, f"{message}; s3 upload failed: {redact_s3_secrets(str(exc), config)}", ran=True)
        message = f"{message}; uploaded to: {uploaded_to}"
    return RuntimeResult(0, message, ran=True)


def _validate_edge_member(member: tarfile.TarInfo) -> str | None:
    path = Path(member.name)
    allowed = {
        Path("edge"),
        Path("edge/compose.yaml"),
        Path("edge/traefik.yml"),
        Path("edge/letsencrypt"),
        Path("edge/letsencrypt/acme.json"),
    }
    if path.is_absolute() or any(part == ".." for part in path.parts):
        return f"edge archive contains unsafe path: {member.name}"
    if path not in allowed:
        return f"edge archive contains unsupported member: {member.name}"
    if member.issym() or member.islnk() or member.isdev():
        return f"edge archive contains unsupported member type: {member.name}"
    return None


def restore_edge(archive_path: str, *, force: bool) -> RuntimeResult:
    """Restore edge."""
    if not force:
        return RuntimeResult(2, "edge restore aborted: --force required")
    source = Path(archive_path)
    if not source.exists():
        return RuntimeResult(2, f"edge backup not found: {archive_path}")
    with tempfile.TemporaryDirectory(prefix="wpfy-edge-restore-") as temp_dir:
        with tarfile.open(source, "r:gz") as archive:
            members = archive.getmembers()
            for member in members:
                error = _validate_edge_member(member)
                if error:
                    return RuntimeResult(2, error)
            archive.extractall(temp_dir, members=members)
        root = Path(temp_dir) / "edge"
        if not root.exists():
            return RuntimeResult(2, "edge archive missing edge root")
        with traefik.traefik_transaction():
            traefik.traefik_dir().mkdir(parents=True, exist_ok=True)
            for source_file, target in (
                (root / "compose.yaml", traefik.traefik_compose_path()),
                (root / "traefik.yml", traefik.traefik_config_path()),
                (root / "letsencrypt" / "acme.json", _local_acme_path()),
            ):
                if source_file.exists():
                    target.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(source_file, target)
                    if target.name == "acme.json":
                        target.chmod(0o600)
            runtime = traefik._restart_traefik_existing_locked()
    if runtime.exit_code != 0:
        return RuntimeResult(runtime.exit_code, f"edge restored; traefik restart failed: {runtime.message}", ran=True)
    return RuntimeResult(0, f"edge restored from {archive_path}; {runtime.message}", ran=True)
