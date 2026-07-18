from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .php_runtime import DEFAULT_PHP_VERSION
from .settings import PATHS
from .site_definition import SiteDefinition
from .site_paths import read_env


class Registry:

    def __init__(self, path: Path | None = None) -> None:
        self._path = path or Path(PATHS.state_dir, "sites.json")
        self._sites: dict[str, dict[str, Any]] = {}
        self._load()

    def _load(self) -> None:
        if self._path.exists():
            try:
                self._sites = json.loads(self._path.read_text(encoding="utf-8")).get("sites", {})
            except json.JSONDecodeError:
                self._sites = {}

    def _save(self) -> None:
        tmp = self._path.with_suffix(".tmp")
        data = {
            "sites": self._sites,
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }
        self._path.parent.mkdir(parents=True, exist_ok=True)
        tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
        os.replace(tmp, self._path)

    def _site_dirs(self, root: Path) -> list[Path]:
        if not root.exists():
            return []
        dirs = []
        for child in sorted(root.iterdir()):
            if child.is_dir() and (child / ".env").exists() and (child / "compose.yaml").exists():
                dirs.append(child)
        return dirs

    def add_site(self, domain: str, metadata: dict[str, Any]) -> None:
        entry = dict(metadata)
        entry.setdefault("domain", domain)
        entry.setdefault("flavor", "unknown")
        entry.setdefault("php_version", DEFAULT_PHP_VERSION)
        entry.setdefault("ssl_enabled", False)
        entry.setdefault("cache_type", "basic")
        if not entry.get("created_at"):
            entry["created_at"] = datetime.now(timezone.utc).isoformat()
        self._sites[domain] = entry
        self._save()

    def update_site(self, domain: str, metadata: dict[str, Any]) -> None:
        existing = self._sites.get(domain, {})
        merged = dict(existing)
        merged.update(metadata)
        merged.setdefault("domain", domain)
        merged.setdefault("created_at", existing.get("created_at", datetime.now(timezone.utc).isoformat()))
        self._sites[domain] = merged
        self._save()

    def remove_site(self, domain: str) -> None:
        self._sites.pop(domain, None)
        self._save()

    def get_site(self, domain: str) -> dict[str, Any] | None:
        entry = self._sites.get(domain)
        return dict(entry) if entry is not None else None

    def list_sites(self) -> list[dict[str, Any]]:
        return [dict(v) for v in self._sites.values()]

    def sync_from_filesystem(self, sites_dir: str | None = None) -> dict[str, Any]:
        added, removed, updated = 0, 0, 0
        root = Path(sites_dir) if sites_dir else Path(PATHS.sites_dir)
        fs_domains: set[str] = set()

        for child in self._site_dirs(root):
            domain = child.name
            fs_domains.add(domain)
            definition = SiteDefinition.from_env(domain, read_env(child / ".env"))
            metadata = definition.registry_metadata()
            existing = self._sites.get(domain)
            if existing:
                metadata["created_at"] = existing.get("created_at", datetime.now(timezone.utc).isoformat())
                if "maintenance" in existing:
                    metadata["maintenance"] = existing["maintenance"]
                if metadata != existing:
                    self._sites[domain] = metadata
                    updated += 1
            else:
                metadata["created_at"] = datetime.now(timezone.utc).isoformat()
                self._sites[domain] = metadata
                added += 1

        stale = [d for d in self._sites if d not in fs_domains]
        for domain in stale:
            del self._sites[domain]
            removed += 1

        if added or removed or updated:
            self._save()

        return {"added": added, "removed": removed, "updated": updated}


_REGISTRY: Registry | None = None


def _get_registry() -> Registry:
    global _REGISTRY
    if _REGISTRY is None:
        _REGISTRY = Registry()
    return _REGISTRY


def add_site(domain: str, metadata: dict[str, Any]) -> None:
    _get_registry().add_site(domain, metadata)


def update_site(domain: str, metadata: dict[str, Any]) -> None:
    _get_registry().update_site(domain, metadata)


def remove_site(domain: str) -> None:
    _get_registry().remove_site(domain)


def get_site(domain: str) -> dict[str, Any] | None:
    return _get_registry().get_site(domain)


def list_sites() -> list[dict[str, Any]]:
    return _get_registry().list_sites()


def sync_from_filesystem(sites_dir: str | None = None) -> dict[str, Any]:
    return _get_registry().sync_from_filesystem(sites_dir)
