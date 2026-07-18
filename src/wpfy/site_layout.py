from __future__ import annotations

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
import tarfile
import tempfile
from urllib.request import urlopen

from .settings import PATHS
from . import registry
from .php_runtime import PHP_IMAGE_REPOSITORY as _PHP_IMAGE_REPOSITORY, php_image
from .s3_backup import S3ConfigError, S3Uploader, load_s3_config, redact_s3_secrets
from .site_definition import MYSQL_FLAVORS, WORDPRESS_FLAVORS, SiteDefinition, sftp_service_lines
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
    _http_probe_site,
    _wait_for_service,
    compose_command,
    docker_available,
    runtime_skip_requested,
    runtime_status,
    site_health,
    start_site_runtime,
    stop_site_runtime,
    wp_cli_command,
)


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
WORDPRESS_VERSION_URL = "https://api.wordpress.org/core/version-check/1.7/"
WORDPRESS_VERSION_RE = re.compile(r"[0-9]+\.[0-9]+(?:\.[0-9]+)?")
WORDPRESS_METADATA_LIMIT = 1024 * 1024
WORDPRESS_DOWNLOAD_CHUNK_SIZE = 1024 * 1024


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
    user = f"{spec.site_uid}:{spec.site_uid}"
    lines = [
        "  web:",
        f"    image: {WEB_IMAGE}",
        f"    container_name: {project}-web",
        "    restart: unless-stopped",
        f'    user: "{user}"',
        "    security_opt:",
        "      - no-new-privileges:true",
        "    cap_drop:",
        "      - NET_RAW",
        "    pids_limit: 256",
        "    mem_limit: 256m",
        "    cpus: 0.50",
        "    logging:",
        "      driver: json-file",
        "      options:",
        "        max-size: 10m",
        "        max-file: \"3\"",
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
            f'      - "traefik.http.routers.{project}-http.middlewares={project}-redirect"',
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
    lines.extend([
        f'      - "traefik.http.services.{project}.loadbalancer.server.port=8080"',
    ])
    lines.extend([
        "    volumes:",
        "      - ./app:/var/www/html:ro",
        "      - ./nginx/default.conf:/etc/nginx/conf.d/default.conf:ro",
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
        "    security_opt:",
        "      - no-new-privileges:true",
        "    cap_drop:",
        "      - NET_RAW",
        "    pids_limit: 512",
        "    mem_limit: 512m",
        "    cpus: 1.00",
        "    logging:",
        "      driver: json-file",
        "      options:",
        "        max-size: 10m",
        "        max-file: \"3\"",
        "    env_file:",
        "      - .env",
        "    networks:",
        "      - site",
        "    volumes:",
        "      - ./app:/var/www/html",
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
            "    security_opt:",
            "      - no-new-privileges:true",
            "    cap_drop:",
            "      - NET_RAW",
            "    pids_limit: 512",
            "    mem_limit: 768m",
            "    cpus: 1.00",
            "    logging:",
            "      driver: json-file",
            "      options:",
            "        max-size: 10m",
            "        max-file: \"3\"",
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
            "    security_opt:",
            "      - no-new-privileges:true",
            "    cap_drop:",
            "      - NET_RAW",
            "    pids_limit: 256",
            "    mem_limit: 256m",
            "    cpus: 0.50",
            "    logging:",
            "      driver: json-file",
            "      options:",
            "        max-size: 10m",
            "        max-file: \"3\"",
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

    lines.extend([
        "",
        "  wpcli:",
        f"    image: {php_image(spec.php_version)}",
        f"    container_name: {project}-wpcli",
        "    profiles:",
        "      - cli",
        f'    user: "{user}"',
        "    security_opt:",
        "      - no-new-privileges:true",
        "    cap_drop:",
        "      - NET_RAW",
        "    pids_limit: 256",
        "    mem_limit: 512m",
        "    cpus: 1.00",
        "    logging:",
        "      driver: json-file",
        "      options:",
        "        max-size: 10m",
        "        max-file: \"3\"",
        "    entrypoint:",
        "      - /usr/local/bin/wp",
        "    env_file:",
        "      - .env",
        "    networks:",
        "      - site",
        "    volumes:",
        "      - ./app:/var/www/html",
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


# Keys fully owned by SiteDefinition.env_values: regeneration adds or drops them
# from .env as the spec dictates (e.g. disabling SFTP removes SFTP_PASSWORD).
# Any other key found in an existing .env was added by the operator and must
# survive regeneration untouched.
MANAGED_ENV_KEYS = {
    "DOMAIN", "COMPOSE_PROJECT_NAME", "SITE_FLAVOR", "APP_ROOT", "PHP_VERSION",
    "SITE_UID", "DB_NAME", "DB_USER", "DB_PASSWORD", "DB_ROOT_PASSWORD",
    "LETSENCRYPT_MODE", "DNS_PROVIDER", "PROXIED", "REDIS_ENABLED",
    "SFTP_PASSWORD", "SFTP_PORT",
}


def env_content(spec: SiteSpec, existing: dict[str, str] | None = None) -> str:
    existing = existing or {}
    values = list(spec.env_values(existing, generated_secret))
    managed = {key for key, _ in values} | MANAGED_ENV_KEYS
    values.extend((key, value) for key, value in existing.items() if key not in managed)
    return "\n".join(f"{key}={value}" for key, value in values) + "\n"


def bootstrap_site_files(domain: str) -> RuntimeResult:
    validate_domain(domain)
    if os.environ.get("WPFY_SKIP_BOOTSTRAP", "0") == "1":
        return RuntimeResult(0, "bootstrap skipped by WPFY_SKIP_BOOTSTRAP=1", skipped=True)

    root = app_dir(domain)
    root.mkdir(parents=True, exist_ok=True)
    health_file = healthcheck_path(domain)
    if not health_file.exists():
        health_file.write_text(f"wpfy-ok {domain}\n", encoding="utf-8")

    flavor = read_env(env_path(domain)).get("SITE_FLAVOR", "site")
    if flavor not in WORDPRESS_FLAVORS:
        # Non-WordPress flavors must never have WordPress core dumped into them.
        if flavor == "html":
            index_html = root / "index.html"
            if not index_html.exists():
                index_html.write_text(
                    "<!doctype html>\n<html lang=\"en\">\n<head><meta charset=\"utf-8\">"
                    f"<title>{domain}</title></head>\n<body><h1>{domain}</h1>"
                    "<p>Static site provisioned by wpfy.</p></body>\n</html>\n",
                    encoding="utf-8",
                )
            return RuntimeResult(0, "static html placeholder created", ran=True)
        index_php = root / "index.php"
        if not index_php.exists():
            index_php.write_text(
                "<?php\n// wpfy placeholder — replace with your application.\n"
                "header('Content-Type: text/plain');\n"
                "echo 'wpfy php site ready';\n",
                encoding="utf-8",
            )
        return RuntimeResult(0, "php site placeholder created", ran=True)

    # WordPress flavors below.
    wp_content = root / "wp-content"
    uploads = wp_content / "uploads"
    wp_content.mkdir(parents=True, exist_ok=True)
    uploads.mkdir(parents=True, exist_ok=True)

    if (root / "index.php").exists() and (root / "wp-config.php").exists():
        return RuntimeResult(0, "wordpress files already bootstrapped", ran=True)

    index_existed = (root / "index.php").exists()
    config_existed = (root / "wp-config.php").exists()
    if os.environ.get("WPFY_SKIP_WORDPRESS_DOWNLOAD", "0") == "1":
        if not index_existed:
            (root / "index.php").write_text("<?php echo 'wpfy bootstrap placeholder';\n", encoding="utf-8")
        if not config_existed:
            (root / "wp-config.php").write_text(
                _wordpress_config_content(read_env(env_path(domain))), encoding="utf-8"
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
            for child in wordpress_root.iterdir():
                destination = root / child.name
                if child.is_dir():
                    shutil.copytree(child, destination, dirs_exist_ok=True)
                else:
                    shutil.copy2(child, destination)

            sample = root / "wp-config-sample.php"
            if sample.exists():
                (root / "wp-config.php").write_text(
                    _wordpress_config_content(read_env(env_path(domain))), encoding="utf-8"
                )

            if not (root / "index.php").exists():
                (root / "index.php").write_text("<?php require __DIR__ . '/wp-blog-header.php';\n", encoding="utf-8")

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
                        'mariadb-dump --single-transaction -u"$MARIADB_USER" '
                        '-p"$MARIADB_PASSWORD" "$MARIADB_DATABASE"',
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
            for entry in (compose_path(domain), env_path(domain), app_dir(domain), nginx_dir(domain), php_dir(domain)):
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
        "if (!defined('ABSPATH')) {",
        "    define('ABSPATH', __DIR__ . '/');",
        "}",
        "require_once ABSPATH . 'wp-settings.php';",
        "",
    ])


def _ensure_wordpress_config(domain: str) -> RuntimeResult:
    config = app_dir(domain) / "wp-config.php"
    if config.exists():
        return RuntimeResult(0, "wp-config.php already exists", ran=True)

    env = read_env(env_path(domain))
    required = ["DB_NAME", "DB_USER", "DB_PASSWORD"]
    missing = [key for key in required if not env.get(key)]
    if missing:
        return RuntimeResult(2, f"missing database settings for wp-config.php: {', '.join(missing)}")

    config.write_text(_wordpress_config_content(env), encoding="utf-8")
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


def _redact_secret(text: str, secret: str) -> str:
    return text.replace(secret, "***REDACTED***") if secret else text


def _wp_cli_error(proc: subprocess.CompletedProcess[str], fallback: str, secret: str = "") -> str:
    message = proc.stderr.strip() or proc.stdout.strip() or fallback
    return _redact_secret(message, secret)


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

    db_ready = _wait_for_service(domain, "db")
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
    if member.issym() or member.islnk():
        return f"backup archive contains unsupported link: {name}"
    if member.isdev():
        return f"backup archive contains unsupported device file: {name}"
    return None


def _extract_tar_safely(archive: tarfile.TarFile, destination: str) -> None:
    """Extract with the stdlib data filter; on Pythons without the filter
    kwarg, reject traversal/link/device members ourselves before extracting."""
    try:
        archive.extractall(destination, filter="data")
    except TypeError:
        members = archive.getmembers()
        for member in members:
            reason = _unsafe_member_reason(member)
            if reason:
                raise RuntimeError(f"refusing to extract archive member with {reason}")
        archive.extractall(destination, members=members)


def _restore_archive_to_temp(source: Path, domain: str, temp_dir: str) -> RuntimeResult | None:
    try:
        with tarfile.open(source, "r:gz") as archive:
            members = archive.getmembers()
            for member in members:
                error = _validate_restore_member(member, domain)
                if error:
                    return RuntimeResult(2, error)
            archive.extractall(temp_dir, members=members)
    except tarfile.TarError as exc:
        return RuntimeResult(2, f"invalid backup archive: {exc}")
    except OSError as exc:
        return RuntimeResult(3, f"failed to read or extract backup archive: {exc}")
    return None


def _preserve_live_db_credentials(domain: str, live_env: dict[str, str]) -> None:
    """Backups carry the SQL dump but not db-data/, so an initialized MariaDB
    volume keeps its pre-restore users. Restoring the archive's old DB
    credentials into .env would break authentication; keep the live ones."""
    keys = ("DB_NAME", "DB_USER", "DB_PASSWORD", "DB_ROOT_PASSWORD")
    preserved = {key: live_env[key] for key in keys if live_env.get(key)}
    if not preserved:
        return
    data_dir = db_data_dir(domain)
    if not data_dir.exists() or not any(data_dir.iterdir()):
        return
    ep = env_path(domain)
    restored = read_env(ep)
    if not restored:
        return
    merged = dict(restored)
    merged.update(preserved)
    if merged == restored:
        return
    ep.write_text("\n".join(f"{key}={value}" for key, value in merged.items()) + "\n", encoding="utf-8")
    ep.chmod(0o600)


def _harden_restored_permissions(domain: str) -> None:
    ep = env_path(domain)
    if ep.exists():
        ep.chmod(0o600)
    backup_root = site_dir(domain) / "backups"
    if backup_root.exists():
        for path in backup_root.glob("*.sql"):
            path.chmod(0o600)


def restore_site(domain: str, archive_path: str) -> RuntimeResult:
    validate_domain(domain)
    source = Path(archive_path)
    if not source.exists():
        return RuntimeResult(2, f"backup not found: {archive_path}")

    # Check disk space before restore
    archive_size = source.stat().st_size
    target = site_dir(domain)
    target.mkdir(parents=True, exist_ok=True)
    disk = shutil.disk_usage(target)
    needed = archive_size * 3  # rough estimate: archive + extracted + safety margin
    if needed > disk.free:
        return RuntimeResult(2,
            f"insufficient disk space: need ~{needed // (1024*1024)}MB, "
            f"available {disk.free // (1024*1024)}MB on {target}"
        )

    with tempfile.TemporaryDirectory(prefix="wpfy-restore-") as temp_dir:
        restore_error = _restore_archive_to_temp(source, domain, temp_dir)
        if restore_error is not None:
            return restore_error

        extracted_root = Path(temp_dir) / domain
        if not extracted_root.exists():
            return RuntimeResult(2, f"backup archive missing site root: {archive_path}")

        # Stop runtime only after archive validation has passed, so rejected archives do not leave sites down.
        if docker_available() and not runtime_skip_requested():
            stop_proc = compose_command(domain, "down")
            if stop_proc.returncode != 0:
                message = stop_proc.stderr.strip() or stop_proc.stdout.strip() or "docker compose down failed"
                return RuntimeResult(stop_proc.returncode, f"failed to stop runtime before restore: {message}")

        live_env = read_env(target / ".env")
        for entry in extracted_root.iterdir():
            destination = target / entry.name
            if destination.exists():
                if destination.is_dir():
                    shutil.rmtree(destination)
                else:
                    destination.unlink()
            if entry.is_dir():
                shutil.copytree(entry, destination)
            else:
                shutil.copy2(entry, destination)

        _preserve_live_db_credentials(domain, live_env)
        _harden_restored_permissions(domain)
        apply_site_ownership(domain)
        sql_files = sorted((target / "backups").glob("*.sql")) if (target / "backups").exists() else []
        if docker_available() and not runtime_skip_requested():
            start_result = start_site_runtime(domain)
            if start_result.exit_code != 0:
                return RuntimeResult(start_result.exit_code, f"failed to start runtime after restore: {start_result.message}")

        if sql_files and docker_available() and not runtime_skip_requested():
            db_ready = _wait_for_service(domain, "db")
            if db_ready.exit_code != 0:
                return db_ready
            latest_sql = sql_files[-1]
            with latest_sql.open("r", encoding="utf-8") as sql_file:
                proc = subprocess.run(
                    [
                        "docker", "compose", "exec", "-T", "db", "sh", "-lc",
                        'mariadb -u"$MARIADB_USER" -p"$MARIADB_PASSWORD" "$MARIADB_DATABASE"',
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

    return RuntimeResult(0, f"site restored from {archive_path}", ran=True)


def list_sites() -> list[dict[str, str]]:
    try:
        sites = registry.list_sites()
        if sites:
            return sites
    except Exception:
        pass
    root = Path(PATHS.sites_dir)
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
    if not path.exists():
        return False
    shutil.rmtree(path)
    registry.remove_site(domain)
    return True


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
    sites_root = Path(PATHS.sites_dir)
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
        (db_data_dir(domain), 0o700, False),
        (redis_data_dir(domain), 0o700, False),
    ]
    try:
        for path, mode, recursive in targets:
            if not path.exists():
                continue
            os.chown(path, uid, uid)
            path.chmod(mode)
            if recursive:
                for child in path.rglob("*"):
                    os.chown(child, uid, uid)
    except PermissionError as exc:
        return RuntimeResult(0, f"ownership skipped (chown not permitted: {exc})", skipped=True)
    return RuntimeResult(0, f"site files owned by uid {uid}", ran=True)


def apply_site_ownership(domain: str) -> RuntimeResult:
    """Re-own a site's host files from its persisted SITE_UID. Used after
    bootstrap, which writes WordPress core as the operator before containers run."""
    value = read_env(env_path(domain)).get("SITE_UID")
    if not value or not value.isdigit():
        return RuntimeResult(0, "ownership skipped (no SITE_UID allocated)", skipped=True)
    return _apply_site_ownership(domain, int(value))


def ensure_site_scaffold(spec: SiteSpec) -> list[str]:
    validate_domain(spec.domain)
    conflict = _project_collision(spec.domain)
    if conflict is not None:
        raise ValueError(
            f"domain {spec.domain} conflicts with existing site {conflict}: "
            f"both map to compose project {domain_to_project(spec.domain)}"
        )
    # Allocate (or reuse) this site's unique uid before rendering the templates,
    # so .env and compose.yaml both carry it.
    env_file = env_path(spec.domain)
    spec = replace(spec, site_uid=_allocate_site_uid(spec.domain, read_env(env_file)))
    touched: list[str] = []
    for path in (
        site_dir(spec.domain),
        nginx_dir(spec.domain),
        php_dir(spec.domain),
        backups_dir(spec.domain),
        db_data_dir(spec.domain) if spec.use_mysql else None,
        redis_data_dir(spec.domain) if spec.use_redis else None,
    ):
        if path is not None and not path.exists():
            path.mkdir(parents=True, exist_ok=True)
            touched.append(str(path))

    compose_file = compose_path(spec.domain)
    if write_if_changed(compose_file, compose_content(spec)):
        touched.append(str(compose_file))
    if write_if_changed(env_file, env_content(spec, read_env(env_file))):
        touched.append(str(env_file))
    env_file.chmod(0o600)
    nginx_file = nginx_conf_path(spec.domain)
    nginx_lines = [
        "server {",
        "    listen 8080;",
        f"    server_name {spec.domain};",
        "    server_tokens off;",
        "    root /var/www/html;",
        "    index index.php index.html;",
        "    autoindex off;",
        # Match the bundled PHP images: upload_max_filesize/post_max_size 64M,
        # max_execution_time 300 (nginx defaults of 1m/60s would 413/504 first).
        "    client_max_body_size 64m;",
        "    add_header X-Content-Type-Options nosniff always;",
        "    add_header X-Frame-Options SAMEORIGIN always;",
        "    add_header Referrer-Policy strict-origin-when-cross-origin always;",
        "    add_header Permissions-Policy \"geolocation=(), microphone=(), camera=()\" always;",
    ]
    if spec.ssl_enabled:
        nginx_lines.append("    add_header Strict-Transport-Security \"max-age=31536000\" always;")
    nginx_lines.extend([
        "    location = /healthz.html {",
        "        access_log off;",
        "        add_header Content-Type text/plain;",
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
        "        fastcgi_read_timeout 300s;",
        "        fastcgi_pass app:9000;",
        "    }",
        "}",
        "",
    ])
    nginx_content = "\n".join(nginx_lines)
    if write_if_changed(nginx_file, nginx_content):
        touched.append(str(nginx_file))
    health_file = healthcheck_path(spec.domain)
    if write_if_changed(health_file, f"wpfy-ok {spec.domain}\n"):
        touched.append(str(health_file))

    metadata = spec.registry_metadata()
    existing_metadata = registry.get_site(spec.domain) or {}
    for key in ("created_at", "maintenance"):
        if key in existing_metadata:
            metadata[key] = existing_metadata[key]
    registry.add_site(spec.domain, metadata)

    if spec.site_uid is not None:
        _apply_site_ownership(spec.domain, spec.site_uid)

    return touched
