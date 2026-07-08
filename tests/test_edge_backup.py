from __future__ import annotations

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
