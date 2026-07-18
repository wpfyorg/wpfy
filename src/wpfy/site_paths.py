from __future__ import annotations

from pathlib import Path
import re

from . import settings


def site_dir(domain: str) -> Path:
    return Path(settings.PATHS.site_dir(domain))


def compose_path(domain: str) -> Path:
    return site_dir(domain) / "compose.yaml"


def env_path(domain: str) -> Path:
    return site_dir(domain) / ".env"


def nginx_dir(domain: str) -> Path:
    return site_dir(domain) / "nginx"


def php_dir(domain: str) -> Path:
    return site_dir(domain) / "php"


def nginx_conf_path(domain: str) -> Path:
    return nginx_dir(domain) / "default.conf"


def healthcheck_path(domain: str) -> Path:
    return app_dir(domain) / "healthz.html"


def backups_dir(domain: str) -> Path:
    return Path(settings.PATHS.state_dir) / "backups" / domain


def app_dir(domain: str) -> Path:
    return site_dir(domain) / "app"


def db_data_dir(domain: str) -> Path:
    return site_dir(domain) / "db-data"


def redis_data_dir(domain: str) -> Path:
    return site_dir(domain) / "redis-data"


def domain_to_project(domain: str) -> str:
    return domain.replace(".", "-").replace("_", "-").lower()


def validate_domain(domain: str) -> None:
    if len(domain) > 253:
        raise ValueError("domain is too long")
    label = r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?"
    if not re.fullmatch(rf"{label}(?:\.{label})+", domain):
        raise ValueError(f"invalid domain: {domain}")


def read_text(path: Path) -> str | None:
    return path.read_text(encoding="utf-8") if path.exists() else None


def read_env(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    text = read_text(path)
    if text is None:
        return values
    for line in text.splitlines():
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key] = value
    return values


def site_exists(domain: str) -> bool:
    try:
        validate_domain(domain)
    except ValueError:
        return False
    return compose_path(domain).exists() and env_path(domain).exists()
