"""Site definition model and validation."""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
import re
from typing import Final

from .image_references import ADMINER_IMAGE, SFTP_IMAGE
from .php_runtime import DEFAULT_PHP_VERSION
from .site_paths import domain_to_project


PAGE_CACHE_OPTIONS: Final = frozenset({
    "none",
    "wpfc",
    "wp-super-cache",
    "w3-total-cache",
    "cache-enabler",
    "wp-fastest-cache",
    "wp-rocket",
    "flying-press",
})
OBJECT_CACHE_OPTIONS: Final = frozenset({"none", "redis"})
LETSENCRYPT_MODES: Final = ("default", "wildcard", "off")
DNS_PROVIDERS: Final = ("cloudflare",)
LEGACY_CACHE_FLAVORS: Final = {
    "wpfc": ("wpfc", "none"),
    "wpredis": ("none", "redis"),
    "wpsc": ("wp-super-cache", "none"),
    "wprocket": ("wp-rocket", "none"),
    "wpce": ("cache-enabler", "none"),
}
WORDPRESS_FLAVORS: Final = frozenset({
    "wp",
    *LEGACY_CACHE_FLAVORS,
    "wpsubdir",
    "wpsubdomain",
})
MYSQL_FLAVORS: Final = frozenset({"mysql", *WORDPRESS_FLAVORS})
DEFAULT_PHP_MEMORY_LIMIT: Final = "256M"
DEFAULT_PHP_MAX_EXECUTION_TIME: Final = "300"
DEFAULT_PHP_MAX_INPUT_TIME: Final = "300"
DEFAULT_PHP_MAX_INPUT_VARS: Final = "3000"
DEFAULT_PHP_UPLOAD_MAX_SIZE: Final = "64M"
_SIZE_VALUE = re.compile(r"^\d{1,6}[KMG]?$")
_INTEGER_VALUE = re.compile(r"^\d{1,6}$")
PHP_SETTING_FIELDS: Final = {
    "php_memory_limit": ("PHP_MEMORY_LIMIT", DEFAULT_PHP_MEMORY_LIMIT, _SIZE_VALUE),
    "php_max_execution_time": ("PHP_MAX_EXECUTION_TIME", DEFAULT_PHP_MAX_EXECUTION_TIME, _INTEGER_VALUE),
    "php_max_input_time": ("PHP_MAX_INPUT_TIME", DEFAULT_PHP_MAX_INPUT_TIME, _INTEGER_VALUE),
    "php_max_input_vars": ("PHP_MAX_INPUT_VARS", DEFAULT_PHP_MAX_INPUT_VARS, _INTEGER_VALUE),
    "php_upload_max_size": ("PHP_UPLOAD_MAX_SIZE", DEFAULT_PHP_UPLOAD_MAX_SIZE, _SIZE_VALUE),
}


def compose_hardening_lines(
    pids_limit: int,
    mem_limit: str,
    cpus: str,
    *,
    cap_add: tuple[str, ...] = (),
) -> list[str]:
    """Compose hardening lines."""
    lines = [
        "    security_opt:",
        "      - no-new-privileges:true",
        "    cap_drop:",
        "      - ALL",
    ]
    if cap_add:
        lines.extend([
            "    cap_add:",
            *(f"      - {capability}" for capability in cap_add),
        ])
    lines.extend([
        f"    pids_limit: {pids_limit}",
        f"    mem_limit: {mem_limit}",
        f"    cpus: {cpus}",
        "    logging:",
        "      driver: json-file",
        "      options:",
        "        max-size: 10m",
        '        max-file: "3"',
    ])
    return lines


def validate_page_cache(value: str) -> str:
    """Validate page cache."""
    if value not in PAGE_CACHE_OPTIONS:
        raise ValueError(f"invalid page cache: {value!r}")
    return value


def validate_object_cache(value: str) -> str:
    """Validate object cache."""
    if value not in OBJECT_CACHE_OPTIONS:
        raise ValueError(f"invalid object cache: {value!r}")
    return value


def validate_adminer_port(value: str) -> str:
    """Validate adminer port."""
    if not isinstance(value, str) or not value.isdigit() or not 1 <= int(value) <= 65535:
        raise ValueError(f"invalid Adminer port: {value!r}")
    return value


def validate_php_setting(name: str, value: str) -> str:
    """Validate php setting."""
    field = PHP_SETTING_FIELDS.get(name)
    if field is None:
        raise ValueError(f"unknown PHP setting: {name}")
    if not isinstance(value, str) or not field[2].fullmatch(value):
        raise ValueError(f"invalid {name}: {value!r}")
    return value


@dataclass(frozen=True)
class SiteDefinition:
    """Site definition and configuration."""
    domain: str
    flavor: str
    use_mysql: bool
    use_redis: bool
    page_cache: str = "none"
    object_cache: str = "none"
    letsencrypt: str | None = None
    dns_provider: str | None = None
    php_version: str = DEFAULT_PHP_VERSION
    ssl_enabled: bool = False
    proxied: bool = False
    sftp_password: str | None = None
    sftp_port: str | None = None
    adminer_port: str | None = None
    php_memory_limit: str = DEFAULT_PHP_MEMORY_LIMIT
    php_max_execution_time: str = DEFAULT_PHP_MAX_EXECUTION_TIME
    php_max_input_time: str = DEFAULT_PHP_MAX_INPUT_TIME
    php_max_input_vars: str = DEFAULT_PHP_MAX_INPUT_VARS
    php_upload_max_size: str = DEFAULT_PHP_UPLOAD_MAX_SIZE
    site_uid: int | None = None

    @classmethod
    def from_env(cls, domain: str, values: dict[str, str]) -> SiteDefinition:
        """Create instance from environment variables."""
        persisted_flavor = values.get("SITE_FLAVOR", "site")
        legacy_page_cache, legacy_object_cache = LEGACY_CACHE_FLAVORS.get(
            persisted_flavor, ("none", "none"),
        )
        flavor = "wp" if persisted_flavor in LEGACY_CACHE_FLAVORS else persisted_flavor
        page_cache = validate_page_cache(values.get("PAGE_CACHE") or legacy_page_cache)
        object_cache = validate_object_cache(
            "redis" if values.get("REDIS_ENABLED") == "1" else legacy_object_cache,
        )
        letsencrypt_value = values.get("LETSENCRYPT_MODE", "")
        letsencrypt = None if letsencrypt_value in ("", "disabled") else letsencrypt_value
        return cls(
            domain=values.get("DOMAIN", domain),
            flavor=flavor,
            use_mysql=flavor in MYSQL_FLAVORS,
            use_redis=object_cache == "redis",
            page_cache=page_cache,
            object_cache=object_cache,
            letsencrypt=letsencrypt,
            dns_provider=values.get("DNS_PROVIDER") or None,
            php_version=values.get("PHP_VERSION", DEFAULT_PHP_VERSION),
            ssl_enabled=bool(letsencrypt),
            proxied=values.get("PROXIED") == "1",
            sftp_password=values.get("SFTP_PASSWORD") or None,
            sftp_port=values.get("SFTP_PORT") or None,
            adminer_port=(
                validate_adminer_port(values["ADMINER_PORT"]) if values.get("ADMINER_PORT") else None
            ),
            php_memory_limit=validate_php_setting(
                "php_memory_limit", values.get("PHP_MEMORY_LIMIT", DEFAULT_PHP_MEMORY_LIMIT),
            ),
            php_max_execution_time=validate_php_setting(
                "php_max_execution_time",
                values.get("PHP_MAX_EXECUTION_TIME", DEFAULT_PHP_MAX_EXECUTION_TIME),
            ),
            php_max_input_time=validate_php_setting(
                "php_max_input_time", values.get("PHP_MAX_INPUT_TIME", DEFAULT_PHP_MAX_INPUT_TIME),
            ),
            php_max_input_vars=validate_php_setting(
                "php_max_input_vars", values.get("PHP_MAX_INPUT_VARS", DEFAULT_PHP_MAX_INPUT_VARS),
            ),
            php_upload_max_size=validate_php_setting(
                "php_upload_max_size", values.get("PHP_UPLOAD_MAX_SIZE", DEFAULT_PHP_UPLOAD_MAX_SIZE),
            ),
            site_uid=int(values["SITE_UID"]) if values.get("SITE_UID") else None,
        )

    def env_values(self, existing: dict[str, str], generated_secret: Callable[[], str]) -> list[tuple[str, str]]:
        """Return environment variable values."""
        project = domain_to_project(self.domain)
        values = [
            ("DOMAIN", self.domain),
            ("COMPOSE_PROJECT_NAME", project),
            ("SITE_FLAVOR", self.flavor),
            ("PAGE_CACHE", validate_page_cache(self.page_cache)),
            ("APP_ROOT", "/var/www/html"),
            ("PHP_VERSION", self.php_version),
            ("PHP_MEMORY_LIMIT", validate_php_setting("php_memory_limit", self.php_memory_limit)),
            (
                "PHP_MAX_EXECUTION_TIME",
                validate_php_setting("php_max_execution_time", self.php_max_execution_time),
            ),
            ("PHP_MAX_INPUT_TIME", validate_php_setting("php_max_input_time", self.php_max_input_time)),
            ("PHP_MAX_INPUT_VARS", validate_php_setting("php_max_input_vars", self.php_max_input_vars)),
            ("PHP_UPLOAD_MAX_SIZE", validate_php_setting("php_upload_max_size", self.php_upload_max_size)),
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
        object_cache = "redis" if self.use_redis else validate_object_cache(self.object_cache)
        if object_cache == "redis":
            values.append(("REDIS_ENABLED", "1"))
        if self.sftp_password:
            values.append(("SFTP_PASSWORD", self.sftp_password))
            values.append(("SFTP_PORT", self.sftp_port or "2222"))
        if self.adminer_port:
            values.append(("ADMINER_PORT", validate_adminer_port(self.adminer_port)))
        return values

    def registry_metadata(self) -> dict[str, object]:
        """Return registry metadata."""
        page_cache = validate_page_cache(self.page_cache)
        object_cache = "redis" if self.use_redis else validate_object_cache(self.object_cache)
        metadata: dict[str, object] = {
            "domain": self.domain,
            "flavor": self.flavor,
            "php_version": self.php_version,
            "ssl_enabled": bool(self.letsencrypt),
            "page_cache": page_cache,
            "object_cache": object_cache,
            "cache_type": object_cache if object_cache != "none" else page_cache if page_cache != "none" else "basic",
        }
        if self.site_uid is not None:
            metadata["site_uid"] = self.site_uid
        if self.sftp_password:
            metadata["sftp_enabled"] = True
        if self.adminer_port:
            metadata["adminer_enabled"] = True
        return metadata


def adminer_service_lines(definition: SiteDefinition) -> list[str]:
    """Adminer service lines."""
    if definition.adminer_port is None:
        raise ValueError("Adminer service requires a port")
    port = validate_adminer_port(definition.adminer_port)
    project = domain_to_project(definition.domain)
    uid = definition.site_uid if definition.site_uid is not None else 1000
    return [
        "  adminer:",
        f"    image: {ADMINER_IMAGE}",
        f"    container_name: {project}-adminer",
        "    restart: unless-stopped",
        f'    user: "{uid}:{uid}"',
        *compose_hardening_lines(128, "128m", "0.25"),
        "    environment:",
        "      ADMINER_DEFAULT_SERVER: db",
        "    depends_on:",
        "      - db",
        "    ports:",
        f'      - "127.0.0.1:{port}:8080"',
        "    networks:",
        "      - site",
    ]


def sftp_service_lines(definition: SiteDefinition) -> list[str]:
    """Sftp service lines."""
    project = domain_to_project(definition.domain)
    uid = definition.site_uid if definition.site_uid is not None else 1000
    return [
        "  sftp:",
        f"    image: {SFTP_IMAGE}",
        f"    container_name: {project}-sftp",
        "    restart: unless-stopped",
        # atmoz/sftp creates the configured account and changes ownership before
        # sshd starts; CHOWN is required by that entrypoint. sshd's privilege
        # separation requires SETUID and SETGID for user-session switching.
        # Port 22 also needs NET_BIND_SERVICE on hosts whose privileged-port
        # floor is 1024.
        *compose_hardening_lines(
            128,
            "128m",
            "0.25",
            cap_add=("CHOWN", "NET_BIND_SERVICE", "SETUID", "SETGID"),
        ),
        "    ports:",
        f'      - "0.0.0.0:{definition.sftp_port or "2222"}:22"',
        f"    command: sftpuser:${{SFTP_PASSWORD}}:{uid}:{uid}:app",
        "    networks:",
        "      - site",
        "    volumes:",
        "      - ./app:/home/sftpuser/app",
    ]
