from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Final

from .php_runtime import DEFAULT_PHP_VERSION
from .site_paths import domain_to_project


WORDPRESS_FLAVORS: Final = frozenset({
    "wp",
    "wpfc",
    "wpredis",
    "wpsc",
    "wprocket",
    "wpce",
    "wpsubdir",
    "wpsubdomain",
})
MYSQL_FLAVORS: Final = frozenset({"mysql", *WORDPRESS_FLAVORS})


@dataclass(frozen=True)
class SiteDefinition:
    domain: str
    flavor: str
    use_mysql: bool
    use_redis: bool
    letsencrypt: str | None = None
    dns_provider: str | None = None
    php_version: str = DEFAULT_PHP_VERSION
    ssl_enabled: bool = False
    proxied: bool = False
    sftp_password: str | None = None
    sftp_port: str | None = None
    site_uid: int | None = None

    @classmethod
    def from_env(cls, domain: str, values: dict[str, str]) -> SiteDefinition:
        flavor = values.get("SITE_FLAVOR", "site")
        letsencrypt_value = values.get("LETSENCRYPT_MODE", "")
        letsencrypt = None if letsencrypt_value in ("", "disabled") else letsencrypt_value
        return cls(
            domain=values.get("DOMAIN", domain),
            flavor=flavor,
            use_mysql=flavor in MYSQL_FLAVORS,
            use_redis=values.get("REDIS_ENABLED") == "1" or flavor == "wpredis",
            letsencrypt=letsencrypt,
            dns_provider=values.get("DNS_PROVIDER") or None,
            php_version=values.get("PHP_VERSION", DEFAULT_PHP_VERSION),
            ssl_enabled=bool(letsencrypt),
            proxied=values.get("PROXIED") == "1",
            sftp_password=values.get("SFTP_PASSWORD") or None,
            sftp_port=values.get("SFTP_PORT") or None,
            site_uid=int(values["SITE_UID"]) if values.get("SITE_UID") else None,
        )

    def env_values(self, existing: dict[str, str], generated_secret: Callable[[], str]) -> list[tuple[str, str]]:
        project = domain_to_project(self.domain)
        values = [
            ("DOMAIN", self.domain),
            ("COMPOSE_PROJECT_NAME", project),
            ("SITE_FLAVOR", self.flavor),
            ("APP_ROOT", "/var/www/html"),
            ("PHP_VERSION", self.php_version),
        ]
        if self.site_uid is not None:
            values.append(("SITE_UID", str(self.site_uid)))
        if self.use_mysql:
            values.extend([
                ("DB_NAME", existing.get("DB_NAME", project)),
                ("DB_USER", existing.get("DB_USER", project)),
                ("DB_PASSWORD", existing.get("DB_PASSWORD", generated_secret())),
                ("DB_ROOT_PASSWORD", existing.get("DB_ROOT_PASSWORD", generated_secret())),
            ])
        if self.letsencrypt:
            values.append(("LETSENCRYPT_MODE", self.letsencrypt))
        if self.dns_provider:
            values.append(("DNS_PROVIDER", self.dns_provider))
        if self.proxied:
            values.append(("PROXIED", "1"))
        if self.use_redis:
            values.append(("REDIS_ENABLED", "1"))
        if self.sftp_password:
            values.append(("SFTP_PASSWORD", self.sftp_password))
            values.append(("SFTP_PORT", self.sftp_port or "2222"))
        return values

    def registry_metadata(self) -> dict[str, object]:
        metadata: dict[str, object] = {
            "domain": self.domain,
            "flavor": self.flavor,
            "php_version": self.php_version,
            "ssl_enabled": bool(self.letsencrypt),
            "cache_type": "redis" if self.use_redis else "basic",
        }
        if self.site_uid is not None:
            metadata["site_uid"] = self.site_uid
        if self.sftp_password:
            metadata["sftp_enabled"] = True
        return metadata


def sftp_service_lines(definition: SiteDefinition) -> list[str]:
    project = domain_to_project(definition.domain)
    uid = definition.site_uid if definition.site_uid is not None else 1000
    return [
        "  sftp:",
        "    image: atmoz/sftp:alpine",
        f"    container_name: {project}-sftp",
        "    restart: unless-stopped",
        "    security_opt:",
        "      - no-new-privileges:true",
        "    cap_drop:",
        "      - NET_RAW",
        "    pids_limit: 128",
        "    mem_limit: 128m",
        "    cpus: 0.25",
        "    logging:",
        "      driver: json-file",
        "      options:",
        "        max-size: 10m",
        "        max-file: \"3\"",
        "    ports:",
        f'      - "127.0.0.1:{definition.sftp_port or "2222"}:22"',
        f"    command: sftpuser:${{SFTP_PASSWORD}}:{uid}:{uid}:app",
        "    networks:",
        "      - site",
        "    volumes:",
        "      - ./app:/home/sftpuser/app",
    ]
