from __future__ import annotations

from collections.abc import Iterable
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
import hashlib
import json
import re
import shutil
import subprocess
import secrets
import os
import stat
import tarfile
import tempfile
from urllib.request import urlopen

from . import registry
from . import site_security
from .events import record_event
from .php_runtime import PHP_IMAGE_REPOSITORY as _PHP_IMAGE_REPOSITORY, php_image
from .redaction import redact_values
from .s3_backup import S3ConfigError, S3Uploader, load_s3_config, redact_s3_secrets
from .site_definition import (
    MYSQL_FLAVORS,
    WORDPRESS_FLAVORS,
    SiteDefinition,
    adminer_service_lines,
    compose_hardening_lines,
    sftp_service_lines,
    validate_php_setting,
)
from .site_paths import (
    app_dir,
    backups_dir,
    compose_path,
    db_data_dir,
    domain_to_project,
    env_path,
    healthcheck_path,
    nginx_conf_path,
    nginx_dir,
    php_dir,
    read_env,
    read_text,
    redis_data_dir,
    site_dir,
    site_exists,
    validate_domain,
)
from .site_runtime import (
    HealthResult,
    RuntimeResult,
    wait_for_service,
    compose_command,
    docker_available,
    runtime_skip_requested,
    runtime_status,
    site_health,
    start_site_runtime,
    stop_site_runtime,
    wp_cli_command,
)


def _current_paths():
    from .settings import PATHS as current_paths

    return current_paths


PHP_IMAGE_REPOSITORY = _PHP_IMAGE_REPOSITORY

# Single source of truth for non-PHP service images: compose_content renders
# these and `wpfy stack install` pre-pulls the same tags.
WEB_IMAGE = "nginxinc/nginx-unprivileged:1.27-alpine"
MARIADB_IMAGE = "mariadb:11.4"
REDIS_IMAGE = "redis:7.2-alpine"

# Base for per-site UID/GID allocation. Each site gets a unique uid (== gid) used
# by every one of its containers and to own its host files, so a compromised (or
# escaped) container from one site has no uid-level path to another site's files,
# database, or cache. The base sits above host system accounts and typical human
# operators; userns-remap is not in use, so the container uid maps 1:1 to the host.
SITE_UID_BASE = 100000

# nginx's add_header inheritance is all-or-nothing: a location that adds a header
# of its own drops every header inherited from the server block. Any location that
# must add one re-emits this list instead of silently shedding the security set.
BASE_SECURITY_HEADERS = (
    "add_header X-Content-Type-Options nosniff always;",
    "add_header X-Frame-Options SAMEORIGIN always;",
    'add_header X-XSS-Protection "0" always;',
    "add_header Referrer-Policy strict-origin-when-cross-origin always;",
    'add_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;',
)
HSTS_HEADER = 'add_header Strict-Transport-Security "max-age=31536000" always;'
WORDPRESS_VERSION_URL = "https://api.wordpress.org/core/version-check/1.7/"
WORDPRESS_VERSION_RE = re.compile(r"[0-9]+\.[0-9]+(?:\.[0-9]+)?")
WORDPRESS_METADATA_LIMIT = 1024 * 1024
WORDPRESS_DOWNLOAD_CHUNK_SIZE = 1024 * 1024
WP_CONFIG_ANCHOR = "/* That's all, stop editing! Happy publishing. */"


SiteSpec = SiteDefinition


def _wordpress_release_version() -> str:
    with urlopen(WORDPRESS_VERSION_URL, timeout=15) as response:
        payload = response.read(WORDPRESS_METADATA_LIMIT + 1)
    if len(payload) > WORDPRESS_METADATA_LIMIT:
        raise ValueError("WordPress release metadata is too large")
    document = json.loads(payload)
    offers = document.get("offers") if isinstance(document, dict) else None
    if not isinstance(offers, list):
        raise ValueError("WordPress release metadata is missing offers")
    for offer in offers:
        if not isinstance(offer, dict):
            continue
        version = offer.get("current")
        if (
            offer.get("response") == "upgrade"
            and offer.get("locale") == "en_US"
            and isinstance(version, str)
            and WORDPRESS_VERSION_RE.fullmatch(version)
        ):
            return version
    raise ValueError("WordPress stable en_US release is unavailable")


def _wordpress_release_sha1(url: str) -> str:
    with urlopen(f"{url}.sha1", timeout=15) as response:
        payload = response.read(WORDPRESS_METADATA_LIMIT + 1)
    if len(payload) > WORDPRESS_METADATA_LIMIT:
        raise ValueError("WordPress release digest is too large")
    digest = payload.decode("ascii").strip().lower()
    if not re.fullmatch(r"[0-9a-f]{40}", digest):
        raise ValueError("WordPress release digest is invalid")
    return digest


def list_backup_archives(domain: str) -> list[Path]:
    validate_domain(domain)
    backups = backups_dir(domain)
    if not backups.exists():
        return []
    archives = [path for path in backups.glob("*.tar.gz") if path.is_file()]
    return sorted(archives, key=lambda path: (path.stat().st_mtime, path.name), reverse=True)


def latest_backup_archive(domain: str) -> RuntimeResult:
    archives = list_backup_archives(domain)
    if not archives:
        return RuntimeResult(2, f"no backup archives found for {domain}")
    return RuntimeResult(0, str(archives[0]), ran=True)


def prune_backup_archives(domain: str, keep: int, *, dry_run: bool = False) -> RuntimeResult:
    validate_domain(domain)
    if keep < 0:
        return RuntimeResult(2, "keep must be 0 or greater")
    archives = list_backup_archives(domain)
    victims = archives[keep:]
    if not victims:
        return RuntimeResult(0, f"no local backups pruned; {len(archives)} retained", ran=not dry_run, skipped=dry_run)
    if dry_run:
        return RuntimeResult(0, f"would prune {len(victims)} local backup(s): " + ", ".join(path.name for path in victims), skipped=True)
    for path in victims:
        path.unlink()
    return RuntimeResult(0, f"pruned {len(victims)} local backup(s); kept {min(keep, len(archives))}", ran=True)


def _router_rule(domain: str, *, wildcard: bool) -> str:
    if not wildcard:
        return f"Host(`{domain}`)"
    escaped = re.escape(domain)
    return f"Host(`{domain}`) || HostRegexp(`^.+\\.{escaped}$`)"


def web_service_lines(spec: SiteSpec) -> list[str]:
    project = domain_to_project(spec.domain)
    if spec.site_uid is None:
        raise ValueError("web_service_lines requires spec.site_uid; allocate it via ensure_site_scaffold")
    router_rule = _router_rule(spec.domain, wildcard=spec.letsencrypt == "wildcard")
    cloudflare_only = site_exists(spec.domain) and site_security.load_security(spec.domain)["cloudflare_only"]
    user = f"{spec.site_uid}:{spec.site_uid}"
    lines = [
        "  web:",
        f"    image: {WEB_IMAGE}",
        f"    container_name: {project}-web",
        "    restart: unless-stopped",
        f'    user: "{user}"',
        *compose_hardening_lines(256, "256m", "0.50"),
        "    depends_on:",
        "      - app",
        "    networks:",
        "      - site",
        "      - wpfy",
        "    labels:",
        '      - "traefik.enable=true"',
        f"      - 'traefik.http.routers.{project}.rule={router_rule}'",
        f'      - "traefik.http.routers.{project}.service={project}"',
    ]
    if spec.ssl_enabled:
        certresolver = "le-dns-cloudflare" if spec.letsencrypt == "wildcard" else "le-http" if spec.proxied else "le"
        lines.extend([
            f'      - "traefik.http.routers.{project}.entrypoints=websecure"',
            f'      - "traefik.http.routers.{project}.tls=true"',
            f'      - "traefik.http.routers.{project}.tls.certresolver={certresolver}"',
            f"      - 'traefik.http.routers.{project}-http.rule={router_rule}'",
            f'      - "traefik.http.routers.{project}-http.entrypoints=web"',
        ])
        if cloudflare_only:
            lines.extend([
                f'      - "traefik.http.routers.{project}.middlewares={project}-cloudflare-only"',
                f'      - "traefik.http.routers.{project}-http.middlewares='
                f'{project}-cloudflare-only,{project}-redirect"',
            ])
        else:
            lines.append(f'      - "traefik.http.routers.{project}-http.middlewares={project}-redirect"')
        lines.extend([
            f'      - "traefik.http.routers.{project}-http.service={project}"',
            f'      - "traefik.http.middlewares.{project}-redirect.redirectscheme.scheme=https"',
        ])
        if spec.letsencrypt == "wildcard":
            lines.extend([
                f'      - "traefik.http.routers.{project}.tls.domains[0].main={spec.domain}"',
                f'      - "traefik.http.routers.{project}.tls.domains[0].sans=*.{spec.domain}"',
            ])
    else:
        lines.append(f'      - "traefik.http.routers.{project}.entrypoints=web"')
        if cloudflare_only:
            lines.append(f'      - "traefik.http.routers.{project}.middlewares={project}-cloudflare-only"')
    if cloudflare_only:
        source_ranges = ",".join(site_security.cloudflare_cidrs())
        lines.append(
            f'      - "traefik.http.middlewares.{project}-cloudflare-only.ipallowlist.sourcerange={source_ranges}"'
        )
    lines.extend([
        f'      - "traefik.http.services.{project}.loadbalancer.server.port=8080"',
    ])
    lines.extend([
        "    volumes:",
        "      - ./app:/var/www/html:ro",
    ])
    if spec.page_cache == "wpfc":
        lines.append("      - ./cache-data:/var/cache/nginx/fastcgi")
    lines.extend([
        "      - ./nginx/cache-path.conf:/etc/nginx/conf.d/00-wpfy-cache-path.conf:ro",
        f"      - ./nginx/{site_security.FORWARDED_SCHEME_SNIPPET}:"
        "/etc/nginx/conf.d/00-wpfy-forwarded-scheme.conf:ro",
        f"      - ./nginx/{site_security.RATELIMIT_SNIPPET}:/etc/nginx/conf.d/00-wpfy-ratelimit.conf:ro",
        "      - ./nginx/wpfy-access.log:/var/log/nginx/wpfy-access.log",
        "      - ./nginx/default.conf:/etc/nginx/conf.d/default.conf:ro",
        f"      - ./nginx/{site_security.HTPASSWD_FILE}:{site_security.HTPASSWD_CONTAINER_PATH}:ro",
        "      - ./nginx/extra:/etc/nginx/wpfy-extra:ro",
        "    healthcheck:",
        "      test: [\"CMD-SHELL\", \"wget -q -O /dev/null http://127.0.0.1:8080/healthz.html\"]",
        "      interval: 30s",
        "      timeout: 10s",
        "      retries: 3",
        "",
    ])
    return lines


def compose_content(spec: SiteSpec) -> str:
    project = domain_to_project(spec.domain)
    if spec.site_uid is None:
        raise ValueError("compose_content requires spec.site_uid; allocate it via ensure_site_scaffold")
    user = f"{spec.site_uid}:{spec.site_uid}"
    db_image = MARIADB_IMAGE
    lines = [f"name: {project}", "services:", *web_service_lines(spec)]
    lines.extend([
        "  app:",
        f"    image: {php_image(spec.php_version)}",
        f"    container_name: {project}-app",
        "    restart: unless-stopped",
        f'    user: "{user}"',
        *compose_hardening_lines(512, "512m", "1.00"),
        "    env_file:",
        "      - .env",
        "    networks:",
        "      - site",
        "    volumes:",
        "      - ./app:/var/www/html",
        "      - ./php/zz-wpfy.ini:/usr/local/etc/php/conf.d/zz-wpfy.ini:ro",
        "      - ./php/custom.ini:/usr/local/etc/php/conf.d/zzz-custom.ini:ro",
        "    healthcheck:",
        "      test: [\"CMD-SHELL\", \"php -v >/dev/null 2>&1\"]",
        "      interval: 30s",
        "      timeout: 10s",
        "      retries: 3",
    ])

    if spec.use_mysql:
        lines.extend([
            "    depends_on:",
            "      - db",
            "",
            "  db:",
            f"    image: {db_image}",
            f"    container_name: {project}-db",
            "    restart: unless-stopped",
            f'    user: "{user}"',
            *compose_hardening_lines(512, "768m", "1.00"),
            "    environment:",
            "      MARIADB_DATABASE: ${DB_NAME}",
            "      MARIADB_USER: ${DB_USER}",
            "      MARIADB_PASSWORD: ${DB_PASSWORD}",
            "      MARIADB_ROOT_PASSWORD: ${DB_ROOT_PASSWORD}",
            "    networks:",
            "      - site",
            "    volumes:",
            "      - ./db-data:/var/lib/mysql",
            "    healthcheck:",
            "      test: [\"CMD-SHELL\", \"mariadb-admin ping -h localhost -u$$MARIADB_USER -p$$MARIADB_PASSWORD --silent\"]",
            "      interval: 30s",
            "      timeout: 10s",
            "      retries: 5",
        ])

    if spec.use_redis:
        lines.extend([
            "",
            "  redis:",
            f"    image: {REDIS_IMAGE}",
            f"    container_name: {project}-redis",
            "    command: [\"redis-server\", \"--appendonly\", \"yes\"]",
            "    restart: unless-stopped",
            f'    user: "{user}"',
            *compose_hardening_lines(256, "256m", "0.50"),
            "    networks:",
            "      - site",
            "    volumes:",
            "      - ./redis-data:/data",
            "    healthcheck:",
            "      test: [\"CMD\", \"redis-cli\", \"ping\"]",
            "      interval: 30s",
            "      timeout: 10s",
            "      retries: 5",
        ])

    if spec.sftp_password:
        lines.append("")
        lines.extend(sftp_service_lines(spec))

    if spec.adminer_port:
        if not spec.use_mysql:
            raise ValueError("Adminer requires a database-enabled site")
        lines.append("")
        lines.extend(adminer_service_lines(spec))

    lines.extend([
        "",
        "  wpcli:",
        f"    image: {php_image(spec.php_version)}",
        f"    container_name: {project}-wpcli",
        "    profiles:",
        "      - cli",
        f'    user: "{user}"',
        *compose_hardening_lines(256, "512m", "1.00"),
        "    entrypoint:",
        "      - /usr/local/bin/wp",
        "    env_file:",
        "      - .env",
        "    networks:",
        "      - site",
        "    volumes:",
        "      - ./app:/var/www/html",
        "      - ./php/zz-wpfy.ini:/usr/local/etc/php/conf.d/zz-wpfy.ini:ro",
        "      - ./php/custom.ini:/usr/local/etc/php/conf.d/zzz-custom.ini:ro",
    ])
    if spec.use_mysql:
        lines.extend([
            "    depends_on:",
            "      - db",
        ])

    lines.extend([
        "",
        "networks:",
        "  site:",
        f"    name: {project}-site",
        "  wpfy:",
        "    external: true",
    ])
    # db/redis use per-site bind-mounted data dirs (./db-data, ./redis-data) owned
    # by the site uid, not named volumes, so no top-level volumes block is needed.

    return "\n".join(lines) + "\n"


def generated_secret() -> str:
    return secrets.token_urlsafe(32)


def php_ini_content(spec: SiteSpec) -> str:
    memory_limit = validate_php_setting("php_memory_limit", spec.php_memory_limit)
    execution_time = validate_php_setting("php_max_execution_time", spec.php_max_execution_time)
    input_time = validate_php_setting("php_max_input_time", spec.php_max_input_time)
    input_vars = validate_php_setting("php_max_input_vars", spec.php_max_input_vars)
    upload_size = validate_php_setting("php_upload_max_size", spec.php_upload_max_size)
    return "\n".join([
        "; Generated by wpfy. Edit php/custom.ini for operator overrides.",
        f"memory_limit = {memory_limit}",
        f"max_execution_time = {execution_time}",
        f"max_input_time = {input_time}",
        f"max_input_vars = {input_vars}",
        f"upload_max_filesize = {upload_size}",
        f"post_max_size = {upload_size}",
        "",
    ])


# Keys fully owned by SiteDefinition.env_values: regeneration adds or drops them
# from .env as the spec dictates (e.g. disabling SFTP removes SFTP_PASSWORD).
# Any other key found in an existing .env was added by the operator and must
# survive regeneration untouched.
MANAGED_ENV_KEYS = {
    "DOMAIN", "COMPOSE_PROJECT_NAME", "SITE_FLAVOR", "PAGE_CACHE", "APP_ROOT", "PHP_VERSION",
    "SITE_UID", "DB_NAME", "DB_USER", "DB_PASSWORD", "DB_ROOT_PASSWORD",
    "LETSENCRYPT_MODE", "DNS_PROVIDER", "PROXIED", "REDIS_ENABLED",
    "SFTP_PASSWORD", "SFTP_PORT", "ADMINER_PORT",
    "PHP_MEMORY_LIMIT", "PHP_MAX_EXECUTION_TIME", "PHP_MAX_INPUT_TIME",
    "PHP_MAX_INPUT_VARS", "PHP_UPLOAD_MAX_SIZE",
}


def env_content(spec: SiteSpec, existing: dict[str, str] | None = None) -> str:
    existing = existing or {}
    values = list(spec.env_values(existing, generated_secret))
    managed = {key for key, _ in values} | MANAGED_ENV_KEYS
    values.extend((key, value) for key, value in existing.items() if key not in managed)
    return "\n".join(f"{key}={value}" for key, value in values) + "\n"


def _destination_symlink(root: Path, destinations: Iterable[Path]) -> Path | None:
    for destination in destinations:
        current = destination
        while True:
            if current.is_symlink():
                return current
            if current == root:
                break
            parent = current.parent
            if parent == current:
                break
            current = parent
    return None


def _tree_symlink(root: Path) -> Path | None:
    for directory, directory_names, file_names in os.walk(root, followlinks=False):
        for name in (*directory_names, *file_names):
            candidate = Path(directory) / name
            if candidate.is_symlink():
                return candidate
    return None


def _merge_tree_safely(
    source_root: Path,
    destination_root: Path,
    excluded_names: Iterable[str] = (),
) -> None:
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    excluded = set(excluded_names)

    def merge(source: Path, destination_fd: int, excluded_children: set[str]) -> None:
        for child in source.iterdir():
            if child.name in excluded_children:
                continue
            mode = child.stat().st_mode & 0o777
            if child.is_dir():
                try:
                    os.mkdir(child.name, mode=mode, dir_fd=destination_fd)
                except FileExistsError:
                    pass
                child_fd = os.open(child.name, directory_flags, dir_fd=destination_fd)
                try:
                    merge(child, child_fd, set())
                finally:
                    os.close(child_fd)
                continue

            file_fd = os.open(
                child.name,
                os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW,
                mode,
                dir_fd=destination_fd,
            )
            with child.open("rb") as source_file, os.fdopen(file_fd, "wb") as destination_file:
                shutil.copyfileobj(source_file, destination_file)
                os.fchmod(destination_file.fileno(), mode)

    root_fd = os.open(destination_root, directory_flags)
    try:
        merge(source_root, root_fd, excluded)
    finally:
        os.close(root_fd)


def _write_text_safely(root: Path, name: str, content: str, mode: int = 0o644) -> None:
    root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        file_fd = os.open(
            name,
            os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW,
            mode,
            dir_fd=root_fd,
        )
        with os.fdopen(file_fd, "w", encoding="utf-8") as destination:
            destination.write(content)
    finally:
        os.close(root_fd)


def _read_text_safely(root: Path, name: str) -> str | None:
    root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        try:
            file_fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=root_fd)
        except FileNotFoundError:
            return None
        with os.fdopen(file_fd, "r", encoding="utf-8") as source:
            return source.read()
    finally:
        os.close(root_fd)


def _file_exists_safely(root: Path, name: str) -> bool:
    root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        try:
            file_fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=root_fd)
        except FileNotFoundError:
            return False
        try:
            if not stat.S_ISREG(os.fstat(file_fd).st_mode):
                raise OSError(f"managed scaffold destination is not a regular file: {name}")
            return True
        finally:
            os.close(file_fd)
    finally:
        os.close(root_fd)


def _read_env_safely(root: Path, name: str) -> dict[str, str]:
    root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        try:
            file_fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=root_fd)
        except FileNotFoundError:
            return {}
        with os.fdopen(file_fd, "r", encoding="utf-8") as source:
            lines = source.read().splitlines()
    finally:
        os.close(root_fd)
    values = {}
    for line in lines:
        if line and not line.startswith("#") and "=" in line:
            key, value = line.split("=", 1)
            values[key] = value
    return values


def _chmod_file_safely(root: Path, name: str, mode: int) -> None:
    root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        file_fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=root_fd)
        try:
            os.fchmod(file_fd, mode)
        finally:
            os.close(file_fd)
    finally:
        os.close(root_fd)


def _ensure_directories_safely(root: Path, names: tuple[str, ...]) -> None:
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    directory_fd = os.open(root, directory_flags)
    try:
        for name in names:
            try:
                os.mkdir(name, dir_fd=directory_fd)
            except FileExistsError:
                pass
            child_fd = os.open(name, directory_flags, dir_fd=directory_fd)
            os.close(directory_fd)
            directory_fd = child_fd
    finally:
        os.close(directory_fd)


def _remove_entries_safely(root: Path, names: Iterable[str]) -> None:
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW

    def clear(directory_fd: int) -> None:
        for name in os.listdir(directory_fd):
            metadata = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            if stat.S_ISDIR(metadata.st_mode):
                child_fd = os.open(name, directory_flags, dir_fd=directory_fd)
                try:
                    clear(child_fd)
                finally:
                    os.close(child_fd)
                os.rmdir(name, dir_fd=directory_fd)
            else:
                os.unlink(name, dir_fd=directory_fd)

    root_fd = os.open(root, directory_flags)
    try:
        for name in names:
            try:
                metadata = os.stat(name, dir_fd=root_fd, follow_symlinks=False)
            except FileNotFoundError:
                continue
            if stat.S_ISDIR(metadata.st_mode):
                child_fd = os.open(name, directory_flags, dir_fd=root_fd)
                try:
                    clear(child_fd)
                finally:
                    os.close(child_fd)
                os.rmdir(name, dir_fd=root_fd)
            else:
                os.unlink(name, dir_fd=root_fd)
    finally:
        os.close(root_fd)


def bootstrap_site_files(domain: str) -> RuntimeResult:
    validate_domain(domain)
    if os.environ.get("WPFY_SKIP_BOOTSTRAP", "0") == "1":
        return RuntimeResult(0, "bootstrap skipped by WPFY_SKIP_BOOTSTRAP=1", skipped=True)

    root = app_dir(domain)
    unsafe = _destination_symlink(root, (root,))
    if unsafe is not None:
        return RuntimeResult(3, "wordpress bootstrap failed: unsafe WordPress destination symlink: app")
    root.mkdir(parents=True, exist_ok=True)
    health_file = healthcheck_path(domain)
    unsafe = _destination_symlink(root, (health_file,))
    if unsafe is not None:
        return RuntimeResult(
            3,
            f"wordpress bootstrap failed: unsafe WordPress destination symlink: {unsafe.relative_to(root)}",
        )
    flavor = read_env(env_path(domain)).get("SITE_FLAVOR", "site")
    if flavor in WORDPRESS_FLAVORS:
        index_path = root / "index.php"
        config_path = root / "wp-config.php"
        unsafe = _tree_symlink(root)
        if unsafe is not None:
            return RuntimeResult(
                3,
                f"wordpress bootstrap failed: unsafe WordPress destination symlink: {unsafe.relative_to(root)}",
            )
        if index_path.exists() and config_path.exists() and health_file.exists():
            return RuntimeResult(0, "wordpress files already bootstrapped", ran=True)
        if docker_available() and not runtime_skip_requested():
            running = compose_command(domain, "ps", "--status", "running", "-q")
            if running.returncode != 0:
                message = running.stderr.strip() or running.stdout.strip() or "runtime status failed"
                return RuntimeResult(3, f"wordpress bootstrap failed: {message}")
            if running.stdout.strip():
                return RuntimeResult(3, "wordpress bootstrap failed: stop the site runtime before retrying")

    if not health_file.exists():
        try:
            _write_text_safely(root, health_file.name, f"wpfy-ok {domain}\n")
        except OSError as exc:
            return RuntimeResult(3, f"wordpress bootstrap failed: {exc}")

    if flavor not in WORDPRESS_FLAVORS:
        # Non-WordPress flavors must never have WordPress core dumped into them.
        if flavor == "html":
            index_html = root / "index.html"
            if index_html.is_symlink():
                return RuntimeResult(3, "static html bootstrap failed: unsafe index.html symlink")
            if not index_html.exists():
                try:
                    _write_text_safely(
                        root,
                        index_html.name,
                        "<!doctype html>\n<html lang=\"en\">\n<head><meta charset=\"utf-8\">"
                        f"<title>{domain}</title></head>\n<body><h1>{domain}</h1>"
                        "<p>Static site provisioned by wpfy.</p></body>\n</html>\n",
                    )
                except OSError as exc:
                    return RuntimeResult(3, f"static html bootstrap failed: {exc}")
            return RuntimeResult(0, "static html placeholder created", ran=True)
        index_php = root / "index.php"
        if index_php.is_symlink():
            return RuntimeResult(3, "php bootstrap failed: unsafe index.php symlink")
        if not index_php.exists():
            try:
                _write_text_safely(
                    root,
                    index_php.name,
                    "<?php\n// wpfy placeholder — replace with your application.\n"
                    "header('Content-Type: text/plain');\n"
                    "echo 'wpfy php site ready';\n",
                )
            except OSError as exc:
                return RuntimeResult(3, f"php bootstrap failed: {exc}")
        return RuntimeResult(0, "php site placeholder created", ran=True)

    # WordPress flavors below.
    index_existed = index_path.exists()
    config_existed = config_path.exists()

    wp_content = root / "wp-content"
    uploads = wp_content / "uploads"
    unsafe = _destination_symlink(root, (wp_content, uploads))
    if unsafe is not None:
        return RuntimeResult(
            3,
            f"wordpress bootstrap failed: unsafe WordPress destination symlink: {unsafe.relative_to(root)}",
        )
    try:
        _ensure_directories_safely(root, (wp_content.name, uploads.name))
    except OSError as exc:
        return RuntimeResult(3, f"wordpress bootstrap failed: {exc}")

    if os.environ.get("WPFY_SKIP_WORDPRESS_DOWNLOAD", "0") == "1":
        try:
            if not index_existed:
                _write_text_safely(root, "index.php", "<?php echo 'wpfy bootstrap placeholder';\n")
            if not config_existed:
                _write_text_safely(
                    root,
                    "wp-config.php",
                    _wordpress_config_content(read_env(env_path(domain))),
                )
        except OSError as exc:
            return RuntimeResult(3, f"wordpress bootstrap failed: {exc}")
        unsafe = _tree_symlink(root)
        if unsafe is not None:
            return RuntimeResult(
                3,
                f"wordpress bootstrap failed: unsafe WordPress destination symlink: {unsafe.relative_to(root)}",
            )
        return RuntimeResult(
            0,
            "wordpress download skipped by WPFY_SKIP_WORDPRESS_DOWNLOAD=1; placeholder files created",
            skipped=True,
        )

    try:
        with tempfile.TemporaryDirectory(prefix="wpfy-wordpress-") as temp_dir:
            version = _wordpress_release_version()
            archive_url = f"https://wordpress.org/wordpress-{version}.tar.gz"
            expected_sha1 = _wordpress_release_sha1(archive_url)
            archive_path = Path(temp_dir) / f"wordpress-{version}.tar.gz"
            actual_sha1 = hashlib.sha1()
            with (
                urlopen(archive_url, timeout=15) as response,
                archive_path.open("wb") as archive_file,
            ):
                while chunk := response.read(WORDPRESS_DOWNLOAD_CHUNK_SIZE):
                    archive_file.write(chunk)
                    actual_sha1.update(chunk)
            if not secrets.compare_digest(actual_sha1.hexdigest(), expected_sha1):
                raise ValueError("WordPress release digest mismatch")
            with tarfile.open(archive_path, "r:gz") as archive:
                _extract_tar_safely(archive, temp_dir)

            wordpress_root = Path(temp_dir) / "wordpress"
            if not wordpress_root.is_dir():
                raise FileNotFoundError("downloaded archive does not contain a wordpress directory")
            destinations = (
                root / source.relative_to(wordpress_root)
                for source in wordpress_root.rglob("*")
            )
            unsafe = _destination_symlink(root, destinations)
            if unsafe is not None:
                raise ValueError(
                    f"unsafe WordPress destination symlink: {unsafe.relative_to(root)}"
                )
            _merge_tree_safely(wordpress_root, root)

            sample = root / "wp-config-sample.php"
            if sample.exists():
                _write_text_safely(
                    root,
                    "wp-config.php",
                    _wordpress_config_content(read_env(env_path(domain))),
                )

            if not (root / "index.php").exists():
                _write_text_safely(root, "index.php", "<?php require __DIR__ . '/wp-blog-header.php';\n")

            unsafe = _tree_symlink(root)
            if unsafe is not None:
                raise ValueError(
                    f"unsafe WordPress destination symlink: {unsafe.relative_to(root)}"
                )

            return RuntimeResult(
                0,
                f"wordpress core {version} verified and bootstrapped from wordpress.org",
                ran=True,
            )
    except (OSError, UnicodeError, tarfile.TarError, TypeError, ValueError) as exc:
        if not index_existed:
            (root / "index.php").unlink(missing_ok=True)
        if not config_existed:
            (root / "wp-config.php").unlink(missing_ok=True)
        return RuntimeResult(3, f"wordpress bootstrap failed: {exc}")


def backup_site(
    domain: str,
    *,
    destination_dir: str | Path | None = None,
    upload_s3: bool = False,
    s3_profile: str | None = None,
    keep_local: int | None = None,
    uploader: S3Uploader | None = None,
    require_database: bool = False,
) -> RuntimeResult:
    validate_domain(domain)
    if not site_exists(domain):
        return RuntimeResult(2, f"site not found: {domain}")

    backups = backups_dir(domain)
    backups.mkdir(parents=True, exist_ok=True)
    backups.chmod(0o750)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    archive_path = backups / f"{domain}-{stamp}.tar.gz"
    archive_staging = backups / f"{domain}-{stamp}.tar.gz.part"
    sql_staging = backups / f"{domain}-{stamp}.sql.part"
    suffix = 1
    while archive_path.exists() or archive_staging.exists() or sql_staging.exists():
        archive_path = backups / f"{domain}-{stamp}-{suffix}.tar.gz"
        archive_staging = backups / f"{domain}-{stamp}-{suffix}.tar.gz.part"
        sql_staging = backups / f"{domain}-{stamp}-{suffix}.sql.part"
        suffix += 1

    flavor = read_env(env_path(domain)).get("SITE_FLAVOR", "site")
    database_required = flavor in MYSQL_FLAVORS
    database_included = False
    try:
        if database_required and docker_available() and not runtime_skip_requested():
            with sql_staging.open("w", encoding="utf-8") as sql_file:
                sql_staging.chmod(0o600)
                proc = subprocess.run(
                    [
                        "docker", "compose", "exec", "-T", "db", "sh", "-lc",
                        'databases="$(mariadb -N -B -uroot -p"$MARIADB_ROOT_PASSWORD" '
                        '-e "SELECT SCHEMA_NAME FROM information_schema.SCHEMATA '
                        "WHERE SCHEMA_NAME NOT IN ('information_schema','performance_schema','mysql','sys') "
                        'ORDER BY SCHEMA_NAME")" && test -n "$databases" && '
                        'mariadb-dump --single-transaction -uroot -p"$MARIADB_ROOT_PASSWORD" '
                        '--databases $databases',
                    ],
                    cwd=site_dir(domain),
                    check=False,
                    text=True,
                    stdout=sql_file,
                    stderr=subprocess.PIPE,
                )
            if proc.returncode != 0 or sql_staging.stat().st_size == 0:
                error = proc.stderr.strip() or "database dump was empty"
                return RuntimeResult(3, f"database backup failed: {error}")
            database_included = True
        elif database_required and require_database:
            return RuntimeResult(3, "database backup required but Docker runtime was unavailable or skipped")

        with tarfile.open(archive_staging, "w:gz") as archive:
            for entry in (
                compose_path(domain),
                env_path(domain),
                site_dir(domain) / site_security.SECURITY_STATE,
                site_dir(domain) / "cron.json",
                app_dir(domain),
                nginx_dir(domain),
                php_dir(domain),
            ):
                if entry is None or not entry.exists():
                    continue
                archive.add(entry, arcname=str(Path(domain) / entry.name), recursive=True)
            if database_included:
                archive.add(
                    sql_staging,
                    arcname=str(Path(domain) / "backups" / f"{archive_path.name.removesuffix('.tar.gz')}.sql"),
                    recursive=False,
                )
        archive_staging.chmod(0o600)

        with tarfile.open(archive_staging, "r:gz") as archive:
            sql_members = [name for name in archive.getnames() if name.endswith(".sql")]
        if database_included and len(sql_members) != 1:
            return RuntimeResult(3, "backup archive verification failed: database member missing or duplicated")
        if require_database and database_required and len(sql_members) != 1:
            return RuntimeResult(3, "backup archive is incomplete: database member missing")
        archive_staging.replace(archive_path)
    except (OSError, tarfile.TarError) as exc:
        return RuntimeResult(3, f"backup creation failed: {exc}")
    finally:
        sql_staging.unlink(missing_ok=True)
        archive_staging.unlink(missing_ok=True)

    message = f"backup created: {archive_path}"
    if database_required and not database_included:
        message = f"{message}; database not included"
    if destination_dir is not None:
        try:
            destination = Path(destination_dir)
            destination.mkdir(parents=True, exist_ok=True)
            destination.chmod(0o700)
            copied_archive = destination / archive_path.name
            shutil.copy2(archive_path, copied_archive)
            copied_archive.chmod(0o600)
        except OSError as exc:
            return RuntimeResult(3, f"{message}; destination copy failed: {exc}", ran=True)
        message = f"{message}; copied to: {copied_archive}"

    if upload_s3:
        try:
            config = load_s3_config(s3_profile)
        except S3ConfigError as exc:
            return RuntimeResult(2, f"{message}; s3 upload skipped: {exc}", ran=True)
        active_uploader = uploader or S3Uploader()
        try:
            uploaded_to = active_uploader.upload_archive(config, archive_path, domain)
        except (OSError, S3ConfigError) as exc:
            return RuntimeResult(4, f"{message}; s3 upload failed: {redact_s3_secrets(str(exc), config)}", ran=True)
        message = f"{message}; uploaded to: {uploaded_to}"

    if keep_local is not None:
        prune = prune_backup_archives(domain, keep_local)
        if prune.exit_code != 0:
            return RuntimeResult(prune.exit_code, f"{message}; retention failed: {prune.message}", ran=True)
        message = f"{message}; retention: {prune.message}"

    record_event("site.backup", domain=domain, detail="site backup completed")
    return RuntimeResult(0, message, ran=True)


def _php_single_quoted(value: str) -> str:
    return "'" + value.replace("\\", "\\\\").replace("'", "\\'") + "'"


def _wordpress_config_content(env: dict[str, str]) -> str:
    salts = "\n".join([
        "define('AUTH_KEY', '" + secrets.token_urlsafe(32) + "');",
        "define('SECURE_AUTH_KEY', '" + secrets.token_urlsafe(32) + "');",
        "define('LOGGED_IN_KEY', '" + secrets.token_urlsafe(32) + "');",
        "define('NONCE_KEY', '" + secrets.token_urlsafe(32) + "');",
        "define('AUTH_SALT', '" + secrets.token_urlsafe(32) + "');",
        "define('SECURE_AUTH_SALT', '" + secrets.token_urlsafe(32) + "');",
        "define('LOGGED_IN_SALT', '" + secrets.token_urlsafe(32) + "');",
        "define('NONCE_SALT', '" + secrets.token_urlsafe(32) + "');",
    ])
    db_name = env.get("DB_NAME", "")
    db_user = env.get("DB_USER", "")
    db_password = env.get("DB_PASSWORD", "")
    return "\n".join([
        "<?php",
        "define('DB_NAME', getenv('DB_NAME') ?: " + _php_single_quoted(db_name) + ");",
        "define('DB_USER', getenv('DB_USER') ?: " + _php_single_quoted(db_user) + ");",
        "define('DB_PASSWORD', getenv('DB_PASSWORD') ?: " + _php_single_quoted(db_password) + ");",
        "define('DB_HOST', 'db');",
        "define('DB_CHARSET', 'utf8mb4');",
        "define('DB_COLLATE', '');",
        salts,
        "$table_prefix = 'wp_';",
        WP_CONFIG_ANCHOR,
        "if (!defined('ABSPATH')) {",
        "    define('ABSPATH', __DIR__ . '/');",
        "}",
        "require_once ABSPATH . 'wp-settings.php';",
        "",
    ])


def repair_wp_config_anchor(domain: str) -> RuntimeResult:
    validate_domain(domain)
    config = app_dir(domain) / "wp-config.php"
    unsafe = _destination_symlink(config.parent, (config,))
    if unsafe is not None:
        return RuntimeResult(2, "unsafe WordPress destination symlink: wp-config.php")

    try:
        content = _read_text_safely(config.parent, config.name)
    except (OSError, UnicodeError) as exc:
        return RuntimeResult(2, f"failed to read wp-config.php for anchor repair: {exc}")
    if content is None:
        return RuntimeResult(0, "wp-config.php anchor repair skipped: config does not exist", skipped=True)
    if WP_CONFIG_ANCHOR in content:
        return RuntimeResult(0, "wp-config.php anchor already present", ran=True)

    table_prefix = content.find("$table_prefix")
    abspath = content.find("if (!defined('ABSPATH')) {")
    require = content.find("require_once ABSPATH . 'wp-settings.php';")
    if table_prefix == -1 or abspath == -1 or require == -1 or not table_prefix < abspath < require:
        return RuntimeResult(0, "wp-config.php anchor repair skipped: unrecognised config shape", skipped=True)

    try:
        _write_text_safely(config.parent, config.name, content[:abspath] + WP_CONFIG_ANCHOR + "\n" + content[abspath:])
    except OSError as exc:
        return RuntimeResult(2, f"failed to repair wp-config.php anchor: {exc}")
    return RuntimeResult(0, "wp-config.php anchor repaired", ran=True)


def _ensure_wordpress_config(domain: str) -> RuntimeResult:
    config = app_dir(domain) / "wp-config.php"
    unsafe = _destination_symlink(config.parent, (config,))
    if unsafe is not None:
        return RuntimeResult(2, "unsafe WordPress destination symlink: wp-config.php")
    if config.exists():
        return RuntimeResult(0, "wp-config.php already exists", ran=True)

    env = read_env(env_path(domain))
    required = ["DB_NAME", "DB_USER", "DB_PASSWORD"]
    missing = [key for key in required if not env.get(key)]
    if missing:
        return RuntimeResult(2, f"missing database settings for wp-config.php: {', '.join(missing)}")

    try:
        _write_text_safely(config.parent, config.name, _wordpress_config_content(env))
    except OSError as exc:
        return RuntimeResult(2, f"failed to create wp-config.php: {exc}")
    return RuntimeResult(0, "wp-config.php created", ran=True)


def wordpress_install_state(domain: str) -> RuntimeResult:
    validate_domain(domain)
    if runtime_skip_requested():
        return RuntimeResult(0, "wordpress install check skipped by WPFY_SKIP_RUNTIME=1", skipped=True)
    if not docker_available():
        return RuntimeResult(0, "wordpress install check skipped because Docker or Compose is unavailable", skipped=True)

    proc = wp_cli_command(domain, "core", "is-installed", "--allow-root")
    if proc.returncode == 0:
        return RuntimeResult(0, "wordpress already installed", ran=True)
    message = proc.stderr.strip() or proc.stdout.strip() or "wordpress is not installed"
    return RuntimeResult(1, message, ran=True)


def _wp_cli_error(proc: subprocess.CompletedProcess[str], fallback: str, secret: str = "") -> str:
    message = proc.stderr.strip() or proc.stdout.strip() or fallback
    return redact_values(message, (secret,))


def provision_wordpress_site(
    domain: str,
    admin_user: str,
    admin_email: str,
    admin_password: str,
) -> RuntimeResult:
    validate_domain(domain)
    if runtime_skip_requested():
        return RuntimeResult(0, "wordpress provisioning skipped by WPFY_SKIP_RUNTIME=1", skipped=True)
    if not docker_available():
        return RuntimeResult(0, "wordpress provisioning skipped because Docker or Compose is unavailable", skipped=True)

    install_state = wordpress_install_state(domain)
    if install_state.exit_code == 0 and install_state.ran:
        return install_state

    db_ready = wait_for_service(domain, "db")
    if db_ready.exit_code != 0:
        return db_ready

    root = app_dir(domain)
    if not (root / "wp-includes" / "version.php").exists():
        download = wp_cli_command(domain, "core", "download", "--force", "--allow-root")
        if download.returncode != 0:
            return RuntimeResult(download.returncode, _wp_cli_error(download, "wp core download failed", admin_password))

    config = _ensure_wordpress_config(domain)
    if config.exit_code != 0:
        return config

    env = read_env(env_path(domain))
    scheme = "https" if env.get("LETSENCRYPT_MODE") else "http"
    db_create = wp_cli_command(domain, "db", "create", "--allow-root")
    if db_create.returncode != 0:
        db_message = db_create.stderr.strip() or db_create.stdout.strip()
        if "database exists" not in db_message.lower() and "database already exists" not in db_message.lower():
            return RuntimeResult(db_create.returncode, _wp_cli_error(db_create, "wp db create failed", admin_password))

    install = wp_cli_command(
        domain,
        "core",
        "install",
        f"--url={scheme}://{domain}",
        f"--title={domain}",
        f"--admin_user={admin_user}",
        f"--admin_email={admin_email}",
        "--skip-email",
        "--allow-root",
        "--prompt=admin_password",
        input_text=admin_password + "\n",
    )
    if install.returncode != 0:
        return RuntimeResult(install.returncode, _wp_cli_error(install, "wp core install failed", admin_password))

    return RuntimeResult(0, f"wordpress installed for {domain} (admin user: {admin_user})", ran=True)


def _unsafe_member_reason(member: tarfile.TarInfo) -> str | None:
    name = member.name
    path = Path(name)
    if path.is_absolute():
        return f"absolute path: {name}"
    if any(part == ".." for part in path.parts):
        return f"unsafe path: {name}"
    if member.issym() or member.islnk():
        return f"unsupported link: {name}"
    if member.isdev():
        return f"unsupported device file: {name}"
    if not member.isfile() and not member.isdir():
        return f"unsupported special file: {name}"
    return None


def _validate_restore_member(member: tarfile.TarInfo, domain: str) -> str | None:
    name = member.name
    path = Path(name)
    if path.is_absolute():
        return f"backup archive contains absolute path: {name}"
    if any(part == ".." for part in path.parts):
        return f"backup archive contains unsafe path: {name}"
    if not path.parts or path.parts[0] != domain:
        return f"backup archive contains data for another site: {name}"
    if len(path.parts) == 1 and not member.isdir():
        return f"backup archive site root is not a directory: {name}"
    if (
        len(path.parts) > 1
        and path.parts[1] == "db-data"
        and (len(path.parts) > 2 or not member.isdir())
    ):
        return f"backup archive contains excluded database volume data: {name}"
    if member.issym() or member.islnk():
        return f"backup archive contains unsupported link: {name}"
    if member.isdev():
        return f"backup archive contains unsupported device file: {name}"
    if not member.isfile() and not member.isdir():
        return f"backup archive contains unsupported special file: {name}"
    return None


def _extract_tar_safely(archive: tarfile.TarFile, destination: str) -> None:
    members = archive.getmembers()
    for member in members:
        reason = _unsafe_member_reason(member)
        if reason:
            raise ValueError(f"unsafe archive member: {reason}")
    try:
        archive.extractall(destination, members=members, filter="data")
    except TypeError:
        archive.extractall(destination, members=members)


def _restore_archive_to_temp(source: Path, domain: str, temp_dir: str) -> RuntimeResult | None:
    try:
        with tarfile.open(source, "r:gz") as archive:
            members = archive.getmembers()
            for member in members:
                error = _validate_restore_member(member, domain)
                if error:
                    return RuntimeResult(2, error)
            _extract_tar_safely(archive, temp_dir)
    except (tarfile.TarError, EOFError) as exc:
        return RuntimeResult(2, f"invalid backup archive: {exc}")
    except OSError as exc:
        return RuntimeResult(3, f"failed to read or extract backup archive: {exc}")
    return None


def _preserve_live_db_credentials(domain: str, live_env: dict[str, str]) -> RuntimeResult | None:
    """Backups carry the SQL dump but not db-data/, so an initialized MariaDB
    volume keeps its pre-restore users. Restoring the archive's old DB
    credentials into .env would break authentication; keep the live ones."""
    keys = ("DB_NAME", "DB_USER", "DB_PASSWORD", "DB_ROOT_PASSWORD")
    preserved = {key: live_env[key] for key in keys if live_env.get(key)}
    if not preserved:
        return None
    data_dir = db_data_dir(domain)
    try:
        data_fd = os.open(data_dir, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except FileNotFoundError:
        return None
    except OSError as exc:
        return RuntimeResult(3, f"failed to inspect live database state: {exc}")
    try:
        initialized = bool(os.listdir(data_fd))
    finally:
        os.close(data_fd)
    if not initialized:
        return None
    target = site_dir(domain)
    try:
        restored = _read_env_safely(target, ".env")
    except OSError as exc:
        return RuntimeResult(3, f"failed to read restored environment: {exc}")
    if not restored:
        return None
    merged = dict(restored)
    merged.update(preserved)
    if merged == restored:
        return None
    try:
        _write_text_safely(
            target, ".env", "\n".join(f"{key}={value}" for key, value in merged.items()) + "\n", 0o600
        )
        _chmod_file_safely(target, ".env", 0o600)
    except OSError as exc:
        return RuntimeResult(3, f"failed to preserve live database credentials: {exc}")
    return None


def _harden_restored_permissions(domain: str) -> RuntimeResult | None:
    target = site_dir(domain)
    try:
        try:
            _chmod_file_safely(target, ".env", 0o600)
        except FileNotFoundError:
            pass
        try:
            _chmod_file_safely(target / "nginx", site_security.HTPASSWD_FILE, 0o640)
        except FileNotFoundError:
            pass
        target_fd = os.open(target, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            try:
                backup_fd = os.open(
                    "backups",
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                    dir_fd=target_fd,
                )
            except FileNotFoundError:
                return None
            try:
                for name in os.listdir(backup_fd):
                    if not name.endswith(".sql"):
                        continue
                    file_fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=backup_fd)
                    try:
                        os.fchmod(file_fd, 0o600)
                    finally:
                        os.close(file_fd)
            finally:
                os.close(backup_fd)
        finally:
            os.close(target_fd)
    except OSError as exc:
        return RuntimeResult(3, f"failed to harden restored permissions: {exc}")
    return None


def restore_site(domain: str, archive_path: str) -> RuntimeResult:
    validate_domain(domain)
    source = Path(archive_path)
    if not source.exists():
        return RuntimeResult(2, f"backup not found: {archive_path}")

    # Check disk space before restore
    archive_size = source.stat().st_size
    target = site_dir(domain)
    if target.is_symlink():
        return RuntimeResult(2, "restore target is an unsafe symlink")
    target.mkdir(parents=True, exist_ok=True)
    unsafe = _tree_symlink(target)
    if unsafe is not None:
        return RuntimeResult(
            2,
            f"restore target contains an unsafe symlink: {unsafe.relative_to(target)}",
        )
    disk = shutil.disk_usage(target)
    needed = archive_size * 3  # rough estimate: archive + extracted + safety margin
    if needed > disk.free:
        return RuntimeResult(
            2,
            f"insufficient disk space: need ~{needed // (1024*1024)}MB, "
            f"available {disk.free // (1024*1024)}MB on {target}",
        )

    with tempfile.TemporaryDirectory(prefix="wpfy-restore-") as temp_dir:
        restore_error = _restore_archive_to_temp(source, domain, temp_dir)
        if restore_error is not None:
            return restore_error

        extracted_root = Path(temp_dir) / domain
        if not extracted_root.exists():
            return RuntimeResult(2, f"backup archive missing site root: {archive_path}")
        if not extracted_root.is_dir():
            return RuntimeResult(2, f"backup archive site root is not a directory: {archive_path}")

        # Stop runtime only after archive validation has passed, so rejected archives do not leave sites down.
        if docker_available() and not runtime_skip_requested():
            stop_proc = compose_command(domain, "down")
            if stop_proc.returncode != 0:
                message = stop_proc.stderr.strip() or stop_proc.stdout.strip() or "docker compose down failed"
                return RuntimeResult(stop_proc.returncode, f"failed to stop runtime before restore: {message}")

        try:
            live_env = _read_env_safely(target, ".env")
        except OSError as exc:
            return RuntimeResult(3, f"failed to read live environment: {exc}")
        restore_names = tuple(entry.name for entry in extracted_root.iterdir() if entry.name != "db-data")
        try:
            _remove_entries_safely(target, restore_names)
            _merge_tree_safely(extracted_root, target, excluded_names=("db-data",))
        except OSError as exc:
            return RuntimeResult(3, f"failed to replace site files during restore: {exc}")

        credential_error = _preserve_live_db_credentials(domain, live_env)
        if credential_error is not None:
            return credential_error
        permission_error = _harden_restored_permissions(domain)
        if permission_error is not None:
            return permission_error
        ownership = apply_site_ownership(domain)
        if ownership.exit_code != 0:
            return ownership
        sql_files = sorted((target / "backups").glob("*.sql")) if (target / "backups").exists() else []
        if docker_available() and not runtime_skip_requested():
            start_result = start_site_runtime(domain)
            if start_result.exit_code != 0:
                return RuntimeResult(start_result.exit_code, f"failed to start runtime after restore: {start_result.message}")

        if sql_files and docker_available() and not runtime_skip_requested():
            db_ready = wait_for_service(domain, "db")
            if db_ready.exit_code != 0:
                return db_ready
            latest_sql = sql_files[-1]
            with latest_sql.open("r", encoding="utf-8") as sql_file:
                proc = subprocess.run(
                    [
                        "docker", "compose", "exec", "-T", "db", "sh", "-lc",
                        'mariadb -uroot -p"$MARIADB_ROOT_PASSWORD"',
                    ],
                    cwd=target,
                    check=False,
                    text=True,
                    stdin=sql_file,
                    capture_output=True,
                )
            if proc.returncode != 0:
                message = proc.stderr.strip() or proc.stdout.strip() or "database restore failed"
                return RuntimeResult(proc.returncode, message)

    record_event("site.restore", domain=domain, detail="site restore completed")
    return RuntimeResult(0, f"site restored from {archive_path}", ran=True)


def list_sites() -> list[dict[str, str]]:
    try:
        sites = registry.list_sites()
        if sites:
            return sites
    except Exception:
        pass
    root = Path(_current_paths().sites_dir)
    if not root.exists():
        return []

    sites = []
    for child in sorted(root.iterdir()):
        if not child.is_dir():
            continue
        env_file = child / ".env"
        compose_file = child / "compose.yaml"
        if not env_file.exists() or not compose_file.exists():
            continue
        env = read_env(env_file)
        sites.append({
            "domain": env.get("DOMAIN", child.name),
            "flavor": env.get("SITE_FLAVOR", "unknown"),
            "path": str(child),
            "compose": str(compose_file),
            "ssl": env.get("LETSENCRYPT_MODE", "disabled"),
            "redis": env.get("REDIS_ENABLED", "0"),
        })
    return sites


def site_info(domain: str) -> dict[str, str]:
    validate_domain(domain)
    try:
        info = registry.get_site(domain)
        if info:
            info["path"] = str(site_dir(domain))
            info["compose"] = str(compose_path(domain))
            info["env"] = str(env_path(domain))
            info["nginx"] = str(nginx_conf_path(domain))
            info["ssl"] = "enabled" if info.get("ssl_enabled") else "disabled"
            info["redis"] = "1" if info.get("cache_type") == "redis" else "0"
            return info
    except Exception:
        pass
    if not site_exists(domain):
        raise FileNotFoundError(f"site not found: {domain}")

    env = read_env(env_path(domain))
    return {
        "domain": env.get("DOMAIN", domain),
        "flavor": env.get("SITE_FLAVOR", "unknown"),
        "path": str(site_dir(domain)),
        "compose": str(compose_path(domain)),
        "env": str(env_path(domain)),
        "nginx": str(nginx_conf_path(domain)),
        "ssl": env.get("LETSENCRYPT_MODE", "disabled"),
        "redis": env.get("REDIS_ENABLED", "0"),
    }


def remove_site_scaffold(domain: str) -> bool:
    validate_domain(domain)
    path = site_dir(domain)
    removed = path.exists()
    if removed:
        shutil.rmtree(path)
        registry.remove_site(domain)
    try:
        rotation_removed = site_security._remove_access_log_rotation(domain)
        configs_changed = site_security._render_fail2ban_configs(skip_invalid=True)
        if (rotation_removed or configs_changed) and site_security.fail2ban_available():
            reload_error = site_security._reload_fail2ban()
            if reload_error:
                record_event(
                    "site.security.fail2ban.reload",
                    domain=domain,
                    outcome="failed",
                    detail="fail2ban reload failed after site removal",
                )
    except OSError:
        pass
    return removed


def write_if_changed(path: Path, content: str) -> bool:
    current = read_text(path)
    if current == content:
        return False
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return True


def _project_collision(domain: str) -> str | None:
    """Return the existing domain whose compose project name collides with this
    one, if any. domain_to_project folds '.' and '_' to '-', so distinct domains
    like a-b.com and a.b.com would otherwise share containers, networks, and
    Traefik routers."""
    project = domain_to_project(domain)
    known: set[str] = set()
    try:
        known.update(site["domain"] for site in registry.list_sites() if site.get("domain"))
    except Exception:
        pass
    sites_root = Path(_current_paths().sites_dir)
    if sites_root.exists():
        for env_file in sites_root.glob("*/.env"):
            known.add(read_env(env_file).get("DOMAIN") or env_file.parent.name)
    for other in sorted(known):
        if other != domain and domain_to_project(other) == project:
            return other
    return None


def _used_site_uids(current_domain: str) -> set[int]:
    used: set[int] = set()
    current_env = env_path(current_domain)
    sites_root = current_env.parent.parent
    if not sites_root.exists():
        return used
    for env_file in sites_root.glob("*/.env"):
        if env_file == current_env:
            continue
        value = read_env(env_file).get("SITE_UID")
        if value and value.isdigit():
            used.add(int(value))
    return used


def _allocate_site_uid(domain: str, env: dict[str, str]) -> int:
    existing = env.get("SITE_UID")
    if existing and existing.isdigit():
        return int(existing)
    used = _used_site_uids(domain)
    uid = SITE_UID_BASE
    while uid in used:
        uid += 1
    return uid


def chown_skip_requested() -> bool:
    return os.environ.get("WPFY_SKIP_CHOWN", "0") == "1"


def _apply_site_ownership(domain: str, uid: int) -> RuntimeResult:
    """Own a site's host files with its per-site uid:gid so other sites' uids
    cannot reach them. Requires root; degrades to a soft skip otherwise."""
    if chown_skip_requested():
        return RuntimeResult(0, "ownership skipped by WPFY_SKIP_CHOWN=1", skipped=True)
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        return RuntimeResult(0, "ownership skipped (wpfy not running as root)", skipped=True)

    targets = [
        (app_dir(domain), 0o750, True),
        (site_dir(domain) / "cache-data", 0o700, False),
        (db_data_dir(domain), 0o700, False),
        (redis_data_dir(domain), 0o700, False),
    ]
    try:
        for path, mode, recursive in targets:
            try:
                metadata = path.lstat()
            except FileNotFoundError:
                continue
            if stat.S_ISLNK(metadata.st_mode):
                return RuntimeResult(3, f"ownership failed: unsafe site ownership symlink: {path.name}")
            directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW

            def own_directory(directory_fd: int) -> None:
                for name in os.listdir(directory_fd):
                    metadata = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                    if stat.S_ISLNK(metadata.st_mode):
                        raise OSError(f"unsafe site ownership symlink: {name}")
                    if stat.S_ISDIR(metadata.st_mode):
                        child_fd = os.open(name, directory_flags, dir_fd=directory_fd)
                        try:
                            os.fchown(child_fd, uid, uid)
                            own_directory(child_fd)
                        finally:
                            os.close(child_fd)
                    else:
                        os.chown(name, uid, uid, dir_fd=directory_fd, follow_symlinks=False)

            path_fd = os.open(path, directory_flags)
            try:
                os.fchown(path_fd, uid, uid)
                os.fchmod(path_fd, mode)
                if recursive:
                    own_directory(path_fd)
            finally:
                os.close(path_fd)

        access_log = nginx_dir(domain) / site_security.ACCESS_LOG_FILE
        try:
            metadata = access_log.lstat()
        except FileNotFoundError:
            pass
        else:
            if stat.S_ISLNK(metadata.st_mode):
                return RuntimeResult(3, f"ownership failed: unsafe access-log symlink: {access_log.name}")
            os.chown(access_log, uid, uid, follow_symlinks=False)
            os.chmod(access_log, 0o640, follow_symlinks=False)
        htpasswd = nginx_dir(domain) / site_security.HTPASSWD_FILE
        try:
            metadata = htpasswd.lstat()
        except FileNotFoundError:
            pass
        else:
            if stat.S_ISLNK(metadata.st_mode):
                return RuntimeResult(3, f"ownership failed: unsafe htpasswd symlink: {htpasswd.name}")
            os.chown(htpasswd, uid, uid, follow_symlinks=False)
            os.chmod(htpasswd, 0o640, follow_symlinks=False)
    except PermissionError as exc:
        return RuntimeResult(0, f"ownership skipped (chown not permitted: {exc})", skipped=True)
    except OSError as exc:
        return RuntimeResult(3, f"ownership failed: {exc}")
    return RuntimeResult(0, f"site files owned by uid {uid}", ran=True)


def apply_site_ownership(domain: str) -> RuntimeResult:
    """Re-own a site's host files from its persisted SITE_UID. Used after
    bootstrap, which writes WordPress core as the operator before containers run."""
    try:
        value = read_env(env_path(domain)).get("SITE_UID")
    except OSError as exc:
        return RuntimeResult(3, f"ownership failed: unsafe site environment: {exc}")
    if not value or not value.isdigit():
        return RuntimeResult(0, "ownership skipped (no SITE_UID allocated)", skipped=True)
    return _apply_site_ownership(domain, int(value))


def get_nginx_custom(domain: str) -> RuntimeResult:
    validate_domain(domain)
    if not site_exists(domain):
        return RuntimeResult(2, f"site not found: {domain}")
    extra_root = nginx_dir(domain) / "extra"
    try:
        content = _read_text_safely(extra_root, "custom.conf")
    except OSError as exc:
        return RuntimeResult(3, f"failed to read nginx custom config: {exc}")
    return RuntimeResult(0, content or "", ran=True)


def _validate_nginx_candidate(domain: str, content: str) -> RuntimeResult:
    if not isinstance(content, str) or "\x00" in content:
        return RuntimeResult(2, "nginx custom config must be text without NUL bytes")
    if runtime_skip_requested() or not docker_available():
        return RuntimeResult(3, "nginx custom config refused: Docker runtime unavailable for validation")

    extra_root = nginx_dir(domain) / "extra"
    candidate_name = f".custom-{secrets.token_hex(8)}.candidate"
    candidate_path = extra_root / candidate_name
    try:
        _write_text_safely(extra_root, candidate_name, content)
        proc = compose_command(
            domain,
            "run",
            "--rm",
            "-T",
            "--no-deps",
            "-v",
            f"{candidate_path}:/etc/nginx/wpfy-extra/custom.conf:ro",
            "web",
            "nginx",
            "-t",
        )
        output = "\n".join(part.strip() for part in (proc.stdout, proc.stderr) if part and part.strip())
        if proc.returncode != 0:
            if 'host not found in upstream "app"' in output.lower():
                return RuntimeResult(
                    proc.returncode or 1,
                    "nginx custom config validation requires the site runtime to be running "
                    "(upstream app was unavailable)",
                )
            return RuntimeResult(proc.returncode or 1, output or "nginx -t failed")
        return RuntimeResult(0, output or "nginx configuration test passed", ran=True)
    except (OSError, subprocess.SubprocessError) as exc:
        return RuntimeResult(3, f"nginx validation failed: {exc}")
    finally:
        try:
            root_fd = os.open(extra_root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.unlink(candidate_name, dir_fd=root_fd)
            except FileNotFoundError:
                pass
            finally:
                os.close(root_fd)
        except OSError:
            pass


def validate_nginx_custom(domain: str, content: str | None = None) -> RuntimeResult:
    validate_domain(domain)
    if not site_exists(domain):
        return RuntimeResult(2, f"site not found: {domain}")
    if content is None:
        current = get_nginx_custom(domain)
        if current.exit_code != 0:
            return current
        content = current.message
    return _validate_nginx_candidate(domain, content)


def _validate_php_candidate(domain: str, content: str) -> RuntimeResult:
    if not isinstance(content, str) or "\x00" in content:
        return RuntimeResult(2, "PHP custom config must be text without NUL bytes")
    if not any(line.strip() and not line.lstrip().startswith(";") for line in content.splitlines()):
        return RuntimeResult(0, "PHP custom config is empty or comments only")
    if runtime_skip_requested() or not docker_available():
        return RuntimeResult(3, "PHP custom config refused: Docker runtime unavailable for validation")

    php_root = php_dir(domain)
    candidate_name = f".custom-{secrets.token_hex(8)}.candidate"
    candidate_path = php_root / candidate_name
    try:
        _write_text_safely(php_root, candidate_name, content)
        proc = compose_command(
            domain,
            "run",
            "--rm",
            "-T",
            "--no-deps",
            "-v",
            f"{candidate_path}:/usr/local/etc/php/conf.d/zzz-custom.ini:ro",
            "app",
            "php",
            "-v",
        )
        output = "\n".join(part.strip() for part in (proc.stdout, proc.stderr) if part and part.strip())
        if "syntax error" in output.lower():
            return RuntimeResult(1, output or "PHP custom config has a syntax error", ran=True)
        if proc.returncode != 0:
            return RuntimeResult(3, output or "PHP custom config validation could not run")
        return RuntimeResult(0, "PHP custom config validation passed", ran=True)
    except (OSError, subprocess.SubprocessError) as exc:
        return RuntimeResult(3, f"PHP custom config validation failed: {exc}")
    finally:
        try:
            root_fd = os.open(php_root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.unlink(candidate_name, dir_fd=root_fd)
            except FileNotFoundError:
                pass
            finally:
                os.close(root_fd)
        except OSError:
            pass


def validate_php_custom(domain: str, content: str | None = None) -> RuntimeResult:
    validate_domain(domain)
    if not site_exists(domain):
        return RuntimeResult(2, f"site not found: {domain}")
    if content is None:
        try:
            content = _read_text_safely(php_dir(domain), "custom.ini")
        except (OSError, UnicodeError) as exc:
            return RuntimeResult(2, f"PHP custom config refused: {exc}")
        if content is None:
            return RuntimeResult(2, f"PHP custom config not found: {domain}")
    return _validate_php_candidate(domain, content)


def set_nginx_custom(domain: str, content: str) -> RuntimeResult:
    validate_domain(domain)
    if not site_exists(domain):
        return RuntimeResult(2, f"site not found: {domain}")
    validation = _validate_nginx_candidate(domain, content)
    if validation.exit_code != 0:
        return validation

    extra_root = nginx_dir(domain) / "extra"
    replacement_name = f".custom-{secrets.token_hex(8)}.replacement"
    try:
        _write_text_safely(extra_root, replacement_name, content)
        root_fd = os.open(extra_root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            try:
                metadata = os.stat("custom.conf", dir_fd=root_fd, follow_symlinks=False)
                if stat.S_ISLNK(metadata.st_mode):
                    return RuntimeResult(3, "nginx custom config refused: custom.conf is a symlink")
            except FileNotFoundError:
                pass
            os.replace(replacement_name, "custom.conf", src_dir_fd=root_fd, dst_dir_fd=root_fd)
        finally:
            os.close(root_fd)
    except OSError as exc:
        return RuntimeResult(3, f"failed to install nginx custom config: {exc}")
    finally:
        try:
            root_fd = os.open(extra_root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.unlink(replacement_name, dir_fd=root_fd)
            except FileNotFoundError:
                pass
            finally:
                os.close(root_fd)
        except OSError:
            pass

    reload_proc = compose_command(domain, "exec", "-T", "web", "nginx", "-s", "reload")
    if reload_proc.returncode != 0:
        output = reload_proc.stderr.strip() or reload_proc.stdout.strip() or "nginx reload failed"
        return RuntimeResult(reload_proc.returncode or 1, f"config validated and installed; {output}", ran=True)
    record_event("site.nginx-custom", domain=domain, detail="validated nginx custom config installed")
    return RuntimeResult(0, validation.message, ran=True)


def ensure_site_scaffold(spec: SiteSpec) -> list[str]:
    validate_domain(spec.domain)
    # Allocate (or reuse) this site's unique uid before rendering the templates,
    # so .env and compose.yaml both carry it.
    site_root = site_dir(spec.domain)
    env_file = env_path(spec.domain)
    managed_paths = (
        site_root,
        site_root / "compose.yaml",
        site_root / ".env",
        site_root / "nginx",
        site_root / "nginx" / "cache-path.conf",
        site_root / "nginx" / site_security.FORWARDED_SCHEME_SNIPPET,
        site_root / "nginx" / site_security.RATELIMIT_SNIPPET,
        site_root / "nginx" / site_security.ACCESS_LOG_FILE,
        site_root / "nginx" / "default.conf",
        site_root / "nginx" / site_security.HTPASSWD_FILE,
        site_root / "nginx" / "extra",
        site_root / "nginx" / "extra" / "custom.conf",
        site_root / "nginx" / "extra" / "wpfy-cache.conf",
        site_root / "nginx" / "extra" / site_security.SECURITY_SNIPPET,
        site_root / site_security.SECURITY_STATE,
        site_root / "php",
        site_root / "php" / "zz-wpfy.ini",
        site_root / "php" / "custom.ini",
        site_root / "backups",
        site_root / "cache-data",
        site_root / "app",
        site_root / "app" / "healthz.html",
        site_root / "db-data" if spec.use_mysql else site_root,
        site_root / "redis-data" if spec.use_redis else site_root,
    )
    unsafe = _destination_symlink(site_root, managed_paths)
    if unsafe is not None:
        raise ValueError(f"unsafe scaffold destination symlink: {unsafe}")
    try:
        conflict = _project_collision(spec.domain)
        existing_env = read_env(env_file)
    except OSError as exc:
        raise ValueError(f"unsafe scaffold destination: {exc}") from exc
    if conflict is not None:
        raise ValueError(
            f"domain {spec.domain} conflicts with existing site {conflict}: "
            f"both map to compose project {domain_to_project(spec.domain)}"
        )
    try:
        spec = replace(spec, site_uid=_allocate_site_uid(spec.domain, existing_env))
    except OSError as exc:
        raise ValueError(f"unsafe scaffold destination: {exc}") from exc
    touched: list[str] = []
    for path in (
        site_root,
        nginx_dir(spec.domain),
        nginx_dir(spec.domain) / "extra",
        php_dir(spec.domain),
        backups_dir(spec.domain),
        site_root / "cache-data" if spec.page_cache == "wpfc" else None,
        db_data_dir(spec.domain) if spec.use_mysql else None,
        redis_data_dir(spec.domain) if spec.use_redis else None,
    ):
        if path is not None and not path.exists():
            path.mkdir(parents=True, exist_ok=True)
            touched.append(str(path))

    health_file = healthcheck_path(spec.domain)
    health_content = f"wpfy-ok {spec.domain}\n"
    try:
        health_file.parent.mkdir(parents=True, exist_ok=True)
        health_current = _read_text_safely(health_file.parent, health_file.name)
    except OSError as exc:
        raise ValueError(f"unsafe healthcheck destination: {exc}") from exc

    nginx_file = nginx_conf_path(spec.domain)
    nginx_lines = [
        "server {",
        "    listen 8080;",
        f"    server_name {spec.domain};",
        "    server_tokens off;",
        "    root /var/www/html;",
        "    index index.php index.html;",
        "    autoindex off;",
        "    access_log /var/log/nginx/wpfy-access.log combined;",
        # Keep nginx's request-body limit aligned with the generated PHP upload limits.
        f"    client_max_body_size {validate_php_setting('php_upload_max_size', spec.php_upload_max_size).lower()};",
        *(f"    {header}" for header in BASE_SECURITY_HEADERS),
        "    include /etc/nginx/wpfy-extra/*.conf;",
    ]
    if spec.ssl_enabled:
        nginx_lines.append(f"    {HSTS_HEADER}")
    nginx_lines.extend([
        "    location = /healthz.html {",
        "        access_log off;",
        "        auth_basic off;",
        "        add_header Content-Type text/plain;",
        "    }",
        "    location = /wp-admin/install.php {",
        "        return 404;",
        "    }",
        "    location = /wp-admin/upgrade.php {",
        "        return 404;",
        "    }",
        "    location ~* ^/wp-content/(?:updraft|uploads/updraft|sucuri|uploads/sucuri)/ {",
        "        return 404;",
        "    }",
        "    location ~* ^/wp-content/uploads/.*\\.php$ {",
        "        return 404;",
        "    }",
        "    location ~* ^/(wp-config\\.php|xmlrpc\\.php|readme\\.html|license\\.txt|docker-compose\\.ya?ml)$ {",
        "        return 404;",
        "    }",
        "    location ~* \\.(?:bak|backup|old|orig|save|sql|sqlite|zip|tar|tgz|gz|log)$ {",
        "        return 404;",
        "    }",
        "    location ~ /\\.(?!well-known(?:/|$)) {",
        "        return 404;",
        "    }",
        "    location / {",
        "        try_files $uri $uri/ /index.php?$args;",
        "    }",
        "    location ~* \\.php$ {",
        "        try_files $uri =404;",
        "        include fastcgi_params;",
        "        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;",
        "        fastcgi_param HTTPS $wpfy_https;",
        "        fastcgi_read_timeout 300s;",
        "        fastcgi_pass app:9000;",
        "    }",
        "}",
        "",
    ])
    nginx_content = "\n".join(nginx_lines)
    compose_file = compose_path(spec.domain)
    compose_rendered = compose_content(spec)
    try:
        env_rendered = env_content(spec, existing_env)
        if _read_text_safely(site_root, env_file.name) != env_rendered:
            _write_text_safely(site_root, env_file.name, env_rendered, 0o600)
            touched.append(str(env_file))
        _chmod_file_safely(site_root, env_file.name, 0o600)

        php_root = php_dir(spec.domain)
        generated_ini = php_ini_content(spec)
        if _read_text_safely(php_root, "zz-wpfy.ini") != generated_ini:
            _write_text_safely(php_root, "zz-wpfy.ini", generated_ini)
            touched.append(str(php_root / "zz-wpfy.ini"))
        if not _file_exists_safely(php_root, "custom.ini"):
            _write_text_safely(php_root, "custom.ini", "")
            touched.append(str(php_root / "custom.ini"))

        nginx_root = nginx_dir(spec.domain)
        if not _file_exists_safely(nginx_root, "cache-path.conf"):
            _write_text_safely(nginx_root, "cache-path.conf", "")
            touched.append(str(nginx_root / "cache-path.conf"))
        if not _file_exists_safely(nginx_root, site_security.RATELIMIT_SNIPPET):
            site_security._safe_write_in_place(nginx_root, site_security.RATELIMIT_SNIPPET, "", 0o644)
            touched.append(str(nginx_root / site_security.RATELIMIT_SNIPPET))
        if not _file_exists_safely(nginx_root, site_security.ACCESS_LOG_FILE):
            site_security._safe_write_in_place(nginx_root, site_security.ACCESS_LOG_FILE, "", 0o640)
            touched.append(str(nginx_root / site_security.ACCESS_LOG_FILE))
        _chmod_file_safely(nginx_root, site_security.ACCESS_LOG_FILE, 0o640)
        site_security._configure_access_log_rotation(spec.domain)
        if not _file_exists_safely(nginx_root, site_security.HTPASSWD_FILE):
            _write_text_safely(nginx_root, site_security.HTPASSWD_FILE, "")
            touched.append(str(nginx_root / site_security.HTPASSWD_FILE))
        _chmod_file_safely(nginx_root, site_security.HTPASSWD_FILE, 0o640)
        extra_root = nginx_root / "extra"
        if not _file_exists_safely(extra_root, "custom.conf"):
            _write_text_safely(extra_root, "custom.conf", "")
            touched.append(str(extra_root / "custom.conf"))
        if _read_text_safely(nginx_file.parent, nginx_file.name) != nginx_content:
            _write_text_safely(nginx_file.parent, nginx_file.name, nginx_content)
            touched.append(str(nginx_file))

        if _read_text_safely(site_root, compose_file.name) != compose_rendered:
            _write_text_safely(site_root, compose_file.name, compose_rendered)
            touched.append(str(compose_file))

        forwarded_scheme_result = site_security.render_forwarded_scheme(spec.domain)
        if forwarded_scheme_result.exit_code != 0:
            raise ValueError(forwarded_scheme_result.message)
        if forwarded_scheme_result.changed:
            touched.append(str(nginx_root / site_security.FORWARDED_SCHEME_SNIPPET))

        security_state = site_root / site_security.SECURITY_STATE
        security_state_existed = security_state.exists()
        security_result = site_security.render_security(spec.domain)
        if security_result.exit_code != 0:
            raise ValueError(security_result.message)
        if not security_state_existed and security_state.exists():
            touched.append(str(security_state))
        if security_result.changed:
            touched.append(str(extra_root / site_security.SECURITY_SNIPPET))
    except OSError as exc:
        raise ValueError(f"unsafe scaffold destination: {exc}") from exc
    try:
        if health_current != health_content:
            _write_text_safely(health_file.parent, health_file.name, health_content)
            touched.append(str(health_file))
    except OSError as exc:
        raise ValueError(f"unsafe healthcheck destination: {exc}") from exc

    config = app_dir(spec.domain) / "wp-config.php"
    if spec.flavor in WORDPRESS_FLAVORS and (config.exists() or config.is_symlink()):
        repair = repair_wp_config_anchor(spec.domain)
        if repair.exit_code != 0:
            raise ValueError(repair.message)
        if repair.skipped:
            record_event("site.wp-config-anchor", domain=spec.domain, outcome="skipped", detail=repair.message)

    metadata = spec.registry_metadata()
    existing_metadata = registry.get_site(spec.domain) or {}
    for key in ("created_at", "maintenance"):
        if key in existing_metadata:
            metadata[key] = existing_metadata[key]
    if metadata != existing_metadata:
        registry.add_site(spec.domain, metadata)

    if spec.site_uid is not None:
        ownership = _apply_site_ownership(spec.domain, spec.site_uid)
        if ownership.exit_code != 0:
            raise ValueError(ownership.message)

    return touched
