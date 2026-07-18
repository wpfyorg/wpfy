from __future__ import annotations

import pytest
import json
from pathlib import Path


def test_registry_add_and_get(clean_registry):
    clean_registry.add_site("example.com", {"flavor": "wp"})
    result = clean_registry.get_site("example.com")
    assert result is not None
    assert result["domain"] == "example.com"
    assert result["flavor"] == "wp"


def test_registry_remove_then_get(clean_registry):
    clean_registry.add_site("example.com", {"flavor": "wp"})
    clean_registry.remove_site("example.com")
    result = clean_registry.get_site("example.com")
    assert result is None


def test_registry_list(clean_registry):
    clean_registry.add_site("one.com", {"flavor": "wp"})
    clean_registry.add_site("two.com", {"flavor": "html"})
    sites = clean_registry.list_sites()
    domains = {s["domain"] for s in sites}
    assert "one.com" in domains
    assert "two.com" in domains


def test_registry_atomic_write(tmp_wpfy_home):
    from wpfy.registry import Registry
    from pathlib import Path

    registry_path = Path(tmp_wpfy_home.state_dir) / "sites.json"
    reg = Registry(path=registry_path)

    reg.add_site("test.com", {"flavor": "wp"})
    assert registry_path.exists()
    data = json.loads(registry_path.read_text(encoding="utf-8"))
    assert "sites" in data
    assert "test.com" in data["sites"]


def test_registry_corruption_recovery(tmp_wpfy_home):
    from wpfy.registry import Registry
    from pathlib import Path

    registry_path = Path(tmp_wpfy_home.state_dir) / "sites.json"
    registry_path.parent.mkdir(parents=True, exist_ok=True)
    registry_path.write_text("not valid json{", encoding="utf-8")

    reg = Registry(path=registry_path)
    assert reg.list_sites() == []


def test_sync_from_filesystem_adds_new_sites(tmp_wpfy_home):
    from wpfy.registry import Registry
    from pathlib import Path

    registry_path = Path(tmp_wpfy_home.state_dir) / "sites.json"
    reg = Registry(path=registry_path)

    site_dir = Path(tmp_wpfy_home.sites_dir) / "newsite.com"
    site_dir.mkdir(parents=True, exist_ok=True)
    (site_dir / ".env").write_text(
        "DOMAIN=newsite.com\nSITE_FLAVOR=wp\nPHP_VERSION=8.2\nLETSENCRYPT_MODE=default\nCACHE_TYPE=basic\nCREATED_AT=2025-01-01\n",
        encoding="utf-8",
    )
    (site_dir / "compose.yaml").write_text("name: newsite-com\nservices:\n  web:\n", encoding="utf-8")

    result = reg.sync_from_filesystem()
    assert result["added"] == 1
    assert result["removed"] == 0
    assert result["updated"] == 0

    site = reg.get_site("newsite.com")
    assert site is not None
    assert site["flavor"] == "wp"
    assert site["ssl_enabled"] is True
    assert site["php_version"] == "8.2"


def test_sync_from_filesystem_missing_php_version_defaults_to_84(tmp_wpfy_home):
    from wpfy.registry import Registry
    from pathlib import Path

    registry_path = Path(tmp_wpfy_home.state_dir) / "sites.json"
    reg = Registry(path=registry_path)

    site_dir = Path(tmp_wpfy_home.sites_dir) / "legacy.com"
    site_dir.mkdir(parents=True, exist_ok=True)
    (site_dir / ".env").write_text(
        "DOMAIN=legacy.com\nSITE_FLAVOR=wp\nLETSENCRYPT_MODE=disabled\nCACHE_TYPE=basic\n",
        encoding="utf-8",
    )
    (site_dir / "compose.yaml").write_text("name: legacy-com\nservices:\n  web:\n", encoding="utf-8")

    reg.sync_from_filesystem()

    site = reg.get_site("legacy.com")
    assert site is not None
    assert site["php_version"] == "8.4"


def test_sync_from_filesystem_removes_stale_sites(tmp_wpfy_home):
    from wpfy.registry import Registry
    from pathlib import Path

    registry_path = Path(tmp_wpfy_home.state_dir) / "sites.json"
    reg = Registry(path=registry_path)
    reg.add_site("stale.com", {"flavor": "html"})

    result = reg.sync_from_filesystem()
    assert result["removed"] == 1
    assert reg.get_site("stale.com") is None
    assert reg.list_sites() == []


def test_sync_from_filesystem_updates_existing(tmp_wpfy_home):
    from wpfy.registry import Registry
    from pathlib import Path

    registry_path = Path(tmp_wpfy_home.state_dir) / "sites.json"
    reg = Registry(path=registry_path)
    reg.add_site("update.com", {"flavor": "wp", "php_version": "8.0"})

    site_dir = Path(tmp_wpfy_home.sites_dir) / "update.com"
    site_dir.mkdir(parents=True, exist_ok=True)
    (site_dir / ".env").write_text(
        "DOMAIN=update.com\nSITE_FLAVOR=wp\nPHP_VERSION=8.3\nLETSENCRYPT_MODE=disabled\nCACHE_TYPE=basic\n",
        encoding="utf-8",
    )
    (site_dir / "compose.yaml").write_text("name: update-com\nservices:\n  web:\n", encoding="utf-8")

    result = reg.sync_from_filesystem()
    assert result["updated"] == 1

    site = reg.get_site("update.com")
    assert site is not None
    assert site["php_version"] == "8.3"


def test_sync_from_filesystem_no_changes_when_identical(tmp_wpfy_home):
    from wpfy.registry import Registry
    from pathlib import Path

    registry_path = Path(tmp_wpfy_home.state_dir) / "sites.json"
    reg = Registry(path=registry_path)
    reg.add_site("same.com", {"flavor": "wp", "php_version": "8.2", "ssl_enabled": False, "cache_type": "basic"})

    site_dir = Path(tmp_wpfy_home.sites_dir) / "same.com"
    site_dir.mkdir(parents=True, exist_ok=True)
    (site_dir / ".env").write_text(
        "DOMAIN=same.com\nSITE_FLAVOR=wp\nPHP_VERSION=8.2\nLETSENCRYPT_MODE=disabled\nCACHE_TYPE=basic\n",
        encoding="utf-8",
    )
    (site_dir / "compose.yaml").write_text("name: same-com\nservices:\n  web:\n", encoding="utf-8")

    result = reg.sync_from_filesystem()
    assert result["added"] == 0
    assert result["removed"] == 0


def test_sync_from_filesystem_ignores_no_env_in_dir(tmp_wpfy_home):
    from wpfy.registry import Registry
    from pathlib import Path

    registry_path = Path(tmp_wpfy_home.state_dir) / "sites.json"
    reg = Registry(path=registry_path)

    site_dir = Path(tmp_wpfy_home.sites_dir) / "nosite"
    site_dir.mkdir(parents=True, exist_ok=True)
    (site_dir / "compose.yaml").write_text("name: nosite\nservices:\n  web:\n", encoding="utf-8")

    result = reg.sync_from_filesystem()
    assert result["added"] == 0
    assert reg.get_site("nosite") is None


def test_update_site_merges_existing_fields(clean_registry):
    clean_registry.add_site("merge.com", {"flavor": "wp", "php_version": "8.2"})
    clean_registry.update_site("merge.com", {"php_version": "8.3"})

    site = clean_registry.get_site("merge.com")
    assert site is not None
    assert site["flavor"] == "wp"
    assert site["php_version"] == "8.3"


def test_registry_get_nonexistent_site(clean_registry):
    result = clean_registry.get_site("nonexistent.com")
    assert result is None


def test_registry_remove_nonexistent_is_noop(clean_registry):
    clean_registry.remove_site("nonexistent.com")
    assert clean_registry.list_sites() == []


def test_sync_from_filesystem_uses_only_supplied_root(tmp_wpfy_home, tmp_path):
    from wpfy.registry import Registry

    alternate = tmp_path / "alternate-sites"
    site = alternate / "alternate.com"
    site.mkdir(parents=True)
    (site / ".env").write_text("DOMAIN=alternate.com\nSITE_FLAVOR=html\n", encoding="utf-8")
    (site / "compose.yaml").write_text("services: {}\n", encoding="utf-8")
    default = Path(tmp_wpfy_home.sites_dir) / "default.com"
    default.mkdir(parents=True)
    (default / ".env").write_text("DOMAIN=default.com\nSITE_FLAVOR=html\n", encoding="utf-8")
    (default / "compose.yaml").write_text("services: {}\n", encoding="utf-8")
    reg = Registry(path=Path(tmp_wpfy_home.state_dir) / "sites.json")

    reg.sync_from_filesystem(str(alternate))

    assert {site["domain"] for site in reg.list_sites()} == {"alternate.com"}


def test_sync_preserves_registry_fields_and_rebuilds_canonical_metadata(tmp_wpfy_home):
    from wpfy.registry import Registry

    reg = Registry(path=Path(tmp_wpfy_home.state_dir) / "sites.json")
    reg.add_site("example.com", {"created_at": "kept", "maintenance": "enabled", "stale": "drop"})
    site = Path(tmp_wpfy_home.sites_dir) / "example.com"
    site.mkdir(parents=True)
    (site / ".env").write_text(
        "DOMAIN=example.com\nSITE_FLAVOR=wpredis\nPHP_VERSION=8.3\nLETSENCRYPT_MODE=default\n"
        "REDIS_ENABLED=1\nSITE_UID=100123\nSFTP_PASSWORD=secret\nSFTP_PORT=2223\n",
        encoding="utf-8",
    )
    (site / "compose.yaml").write_text("services: {}\n", encoding="utf-8")

    reg.sync_from_filesystem()

    assert reg.get_site("example.com") == {
        "domain": "example.com",
        "flavor": "wpredis",
        "php_version": "8.3",
        "ssl_enabled": True,
        "cache_type": "redis",
        "site_uid": 100123,
        "sftp_enabled": True,
        "created_at": "kept",
        "maintenance": "enabled",
    }


def test_sync_noop_preserves_registry_bytes_and_mtime(tmp_wpfy_home):
    from wpfy.registry import Registry

    path = Path(tmp_wpfy_home.state_dir) / "sites.json"
    reg = Registry(path=path)
    site = Path(tmp_wpfy_home.sites_dir) / "same.com"
    site.mkdir(parents=True)
    (site / ".env").write_text("DOMAIN=same.com\nSITE_FLAVOR=wp\nPHP_VERSION=8.4\n", encoding="utf-8")
    (site / "compose.yaml").write_text("services: {}\n", encoding="utf-8")
    reg.sync_from_filesystem()
    before = (path.read_bytes(), path.stat().st_mtime_ns)

    assert reg.sync_from_filesystem() == {"added": 0, "removed": 0, "updated": 0}
    assert (path.read_bytes(), path.stat().st_mtime_ns) == before
