from __future__ import annotations

import io
import tarfile
from pathlib import Path


def _patch_traefik_paths(monkeypatch, module, root: Path) -> None:
    monkeypatch.setattr(module.traefik, "traefik_dir", lambda: root)
    monkeypatch.setattr(module.traefik, "traefik_compose_path", lambda: root / "compose.yaml")
    monkeypatch.setattr(module.traefik, "traefik_config_path", lambda: root / "traefik.yml")


def test_backup_edge_archives_config_and_acme(tmp_path, monkeypatch):
    import wpfy.edge_backup

    monkeypatch.setenv("WPFY_SKIP_RUNTIME", "1")
    root = tmp_path / "traefik"
    _patch_traefik_paths(monkeypatch, wpfy.edge_backup, root)
    (root / "letsencrypt").mkdir(parents=True)
    (root / "compose.yaml").write_text("services: {}\n", encoding="utf-8")
    (root / "traefik.yml").write_text("api: {}\n", encoding="utf-8")
    (root / "letsencrypt" / "acme.json").write_text('{"secret":"do-not-print"}\n', encoding="utf-8")

    result = wpfy.edge_backup.backup_edge(destination_dir=tmp_path)

    assert result.exit_code == 0
    assert "do-not-print" not in result.message
    archive_path = Path(result.message.removeprefix("edge backup created: "))
    with tarfile.open(archive_path, "r:gz") as archive:
        assert set(archive.getnames()) >= {"edge/compose.yaml", "edge/traefik.yml", "edge/letsencrypt/acme.json"}


def test_backup_edge_uploads_with_shared_file_signer(tmp_path, monkeypatch):
    import wpfy.edge_backup
    from wpfy.s3_backup import S3Uploader

    monkeypatch.setenv("WPFY_SKIP_RUNTIME", "1")
    monkeypatch.setenv("WPFY_BACKUP_S3_ENDPOINT", "https://storage.example.test")
    monkeypatch.setenv("WPFY_BACKUP_S3_BUCKET", "site-backups")
    monkeypatch.setenv("WPFY_BACKUP_S3_REGION", "auto")
    monkeypatch.setenv("WPFY_BACKUP_S3_ACCESS_KEY", "access-key")
    monkeypatch.setenv("WPFY_BACKUP_S3_SECRET_KEY", "secret-key")
    root = tmp_path / "traefik"
    _patch_traefik_paths(monkeypatch, wpfy.edge_backup, root)
    root.mkdir()
    (root / "compose.yaml").write_text("services: {}\n", encoding="utf-8")
    observed = {}

    class Response(io.BytesIO):
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *args):
            self.close()

    def opener(request, *, timeout):
        observed["authorization"] = request.headers["Authorization"]
        observed["file_body"] = not isinstance(request.data, bytes)
        return Response()

    result = wpfy.edge_backup.backup_edge(
        destination_dir=tmp_path / "backups",
        upload_s3=True,
        uploader=S3Uploader(opener),
    )

    assert result.exit_code == 0
    assert observed["file_body"] is True
    assert "SignedHeaders=content-length;host;x-amz-content-sha256;x-amz-date" in observed["authorization"]
    assert Path(result.message.split(";", 1)[0].removeprefix("edge backup created: ")).exists()


def test_backup_edge_upload_failure_preserves_archive_and_redacts_secret(tmp_path, monkeypatch):
    import wpfy.edge_backup
    from wpfy.s3_backup import S3Uploader

    monkeypatch.setenv("WPFY_SKIP_RUNTIME", "1")
    monkeypatch.setenv("WPFY_BACKUP_S3_ENDPOINT", "https://storage.example.test")
    monkeypatch.setenv("WPFY_BACKUP_S3_BUCKET", "site-backups")
    monkeypatch.setenv("WPFY_BACKUP_S3_REGION", "auto")
    monkeypatch.setenv("WPFY_BACKUP_S3_ACCESS_KEY", "access-key")
    monkeypatch.setenv("WPFY_BACKUP_S3_SECRET_KEY", "secret-key")
    root = tmp_path / "traefik"
    _patch_traefik_paths(monkeypatch, wpfy.edge_backup, root)
    root.mkdir()
    (root / "compose.yaml").write_text("services: {}\n", encoding="utf-8")

    def fail_upload(request, *, timeout):
        raise OSError("upload denied for secret-key")

    result = wpfy.edge_backup.backup_edge(
        destination_dir=tmp_path / "backups",
        upload_s3=True,
        uploader=S3Uploader(fail_upload),
    )

    local_path = Path(result.message.split(";", 1)[0].removeprefix("edge backup created: "))
    assert result.exit_code != 0
    assert local_path.exists()
    assert "secret-key" not in result.message
    assert "***REDACTED***" in result.message


def test_restore_edge_validates_then_restarts_without_regenerating(tmp_path, monkeypatch):
    import wpfy.edge_backup
    from wpfy.site_layout import RuntimeResult

    target_root = tmp_path / "traefik-target"
    _patch_traefik_paths(monkeypatch, wpfy.edge_backup, target_root)
    archive_root = tmp_path / "edge"
    (archive_root / "letsencrypt").mkdir(parents=True)
    (archive_root / "compose.yaml").write_text("name: restored\nservices: {}\n", encoding="utf-8")
    (archive_root / "traefik.yml").write_text("restored-config\n", encoding="utf-8")
    (archive_root / "letsencrypt" / "acme.json").write_text("{}\n", encoding="utf-8")
    archive_path = tmp_path / "edge.tar.gz"
    with tarfile.open(archive_path, "w:gz") as archive:
        archive.add(archive_root, arcname="edge")
    calls = []
    monkeypatch.setattr(
        wpfy.edge_backup.traefik,
        "restart_traefik_existing",
        lambda: calls.append("restart") or RuntimeResult(0, "restarted", ran=True),
    )

    result = wpfy.edge_backup.restore_edge(str(archive_path), force=True)

    assert result.exit_code == 0
    assert calls == ["restart"]
    assert (target_root / "traefik.yml").read_text(encoding="utf-8") == "restored-config\n"
