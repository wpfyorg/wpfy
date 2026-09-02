"""Site directory paths and domain validation."""
from __future__ import annotations

import os
from pathlib import Path
import re

from . import settings


def site_dir(domain: str) -> Path:
    """Return site directory."""
    return Path(settings.PATHS.site_dir(domain))


def compose_path(domain: str) -> Path:
    """Return compose path."""
    return site_dir(domain) / "compose.yaml"


def env_path(domain: str) -> Path:
    """Return env path."""
    return site_dir(domain) / ".env"


def nginx_dir(domain: str) -> Path:
    """Return nginx directory."""
    return site_dir(domain) / "nginx"


def php_dir(domain: str) -> Path:
    """Return php directory."""
    return site_dir(domain) / "php"


def nginx_conf_path(domain: str) -> Path:
    """Return nginx conf path."""
    return nginx_dir(domain) / "default.conf"


def healthcheck_path(domain: str) -> Path:
    """Return healthcheck path."""
    return app_dir(domain) / "healthz.html"


def backups_dir(domain: str) -> Path:
    """Return backups directory."""
    return Path(settings.PATHS.state_dir) / "backups" / domain


def app_dir(domain: str) -> Path:
    """Return app directory."""
    return site_dir(domain) / "app"


def db_data_dir(domain: str) -> Path:
    """Return db data directory."""
    return site_dir(domain) / "db-data"


def redis_data_dir(domain: str) -> Path:
    """Return redis data directory."""
    return site_dir(domain) / "redis-data"


def domain_to_project(domain: str) -> str:
    """Domain to project."""
    return domain.replace(".", "-").replace("_", "-").lower()


def validate_domain(domain: str) -> None:
    """Validate domain."""
    if len(domain) > 253:
        raise ValueError("domain is too long")
    label = r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?"
    if not re.fullmatch(rf"{label}(?:\.{label})+", domain):
        raise ValueError(f"invalid domain: {domain}")


def read_text(path: Path) -> str | None:
    """Read text."""
    return path.read_text(encoding="utf-8") if path.exists() else None


def read_env(path: Path) -> dict[str, str]:
    """Read env."""
    values: dict[str, str] = {}
    try:
        parent_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except FileNotFoundError:
        return values
    try:
        try:
            file_fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent_fd)
        except FileNotFoundError:
            return values
        with os.fdopen(file_fd, "r", encoding="utf-8") as source:
            text = source.read()
    finally:
        os.close(parent_fd)
    for line in text.splitlines():
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key] = value
    return values


def site_exists(domain: str) -> bool:
    """Site exists."""
    try:
        validate_domain(domain)
    except ValueError:
        return False
    return compose_path(domain).exists() and env_path(domain).exists()
