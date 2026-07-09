from __future__ import annotations

import argparse
import base64
from datetime import datetime
import getpass
import hashlib
import importlib.metadata
import json
import os
import re
import secrets
import shlex
import shutil
import smtplib
import subprocess
import string
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Final, Iterable
from urllib.error import URLError
from urllib.request import Request, urlopen

from . import __version__
from . import backup_schedule
from . import cron
from . import dns
from . import edge_backup
from . import registry
from . import smtp
from . import sftp
from . import site_lifecycle
from . import traefik
from . import operational_inspection
from .php_runtime import DEFAULT_PHP_VERSION, PHP_IMAGE_REPOSITORY, SUPPORTED_PHP_VERSIONS, php_image
from .certificate_lifecycle import cert_expiry_days, force_renew_cert, get_cert_info, preflight_ssl
from .site_definition import SiteDefinition
from .s3_backup import (
    S3Config,
    S3Uploader,
    clear_s3_config,
    load_s3_config,
    redact_s3_secrets,
    s3_config_path,
    s3_object_key,
    write_s3_config,
)
from .smtp import SMTPConfig
from .site_layout import (
    MARIADB_IMAGE,
    REDIS_IMAGE,
    WORDPRESS_FLAVORS,
    backup_site,
    compose_command,
    compose_path,
    domain_to_project,
    env_path,
    ensure_site_scaffold,
    generated_secret,
    latest_backup_archive,
    list_backup_archives,
    list_sites,
    nginx_conf_path,
    read_env,
    remove_site_scaffold,
    prune_backup_archives,
    restore_site,
    runtime_skip_requested,
    site_health,
    site_info,
    site_exists,
    site_dir,
    start_site_runtime,
    stop_site_runtime,
    validate_domain,
)


class WpfyHelpFormatter(argparse.ArgumentDefaultsHelpFormatter, argparse.RawDescriptionHelpFormatter):
    pass


@dataclass(frozen=True, slots=True)
class CommandResult:
    message: str
    exit_code: int = 0


def _show_progress() -> bool:
    return sys.stderr.isatty() and os.environ.get("WPFY_NO_PROGRESS", "0") != "1"


def _progress(message: str) -> None:
    if _show_progress():
        print(message, file=sys.stderr, flush=True)


def _section(title: str) -> str:
    return f"=== {title} ==="


def _render_summary(title: str, lines: list[str]) -> str:
    return "\n".join([_section(title), *lines])


def _step_status(result: RuntimeResult) -> str:
    if result.skipped:
        return "SKIP"
    if result.exit_code != 0:
        return "FAIL"
    return "OK"


def _step_line(label: str, result: RuntimeResult) -> str:
    return f"{label}: {_step_status(result)} {result.message}".rstrip()


def _bool_text(value: bool) -> str:
    return "yes" if value else "no"


def _enabled_text(value: str | bool) -> str:
    if isinstance(value, bool):
        return "enabled" if value else "disabled"
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"1", "true", "yes", "enabled", "on"}:
            return "enabled"
        if normalized in {"0", "false", "no", "disabled", "off"}:
            return "disabled"
        return value.strip()
    return str(value)


def _site_count_summary(touched: list[str]) -> str:
    return "unchanged" if not touched else f"updated {len(touched)} paths"


def _site_type_label(flavor: str) -> str:
    if flavor in WORDPRESS_FLAVORS:
        return "wordpress"
    if flavor == "html":
        return "static html"
    if flavor == "mysql":
        return "mysql-backed php"
    return "php site"


def _site_create_next_steps(domain: str, flavor: str) -> list[str]:
    steps: list[str] = []
    if flavor in WORDPRESS_FLAVORS:
        steps.append(f"sign in at https://{domain}/wp-admin")
    if flavor in {"wpfc", "wpsc", "wprocket", "wpce"}:
        steps.append("install and activate the matching cache plugin in WordPress")
    if flavor == "wpredis":
        steps.append("install and activate a Redis cache plugin, then enable object cache in WordPress")
    return steps


def _format_site_create_result(
    domain: str,
    flavor: str,
    scaffold_summary: str,
    bootstrap: RuntimeResult,
    runtime: RuntimeResult,
    wordpress_message: str | None = None,
    wordpress_admin_user: str | None = None,
    generated_password: str | None = None,
    preflight_message: str | None = None,
    created: bool = True,
) -> str:
    heading = "Site created" if created else "Site already up to date"
    lines = [
        f"domain: {domain}",
        f"site type: {_site_type_label(flavor)}",
        f"scaffold: {scaffold_summary}",
        _step_line("bootstrap", bootstrap),
        _step_line("runtime", runtime),
    ]
    if preflight_message:
        lines.append(f"preflight: {preflight_message}")
    if wordpress_message:
        lines.append(f"wordpress: {wordpress_message}")
    if wordpress_admin_user:
        lines.append(f"admin user: {wordpress_admin_user}")
    if generated_password:
        lines.append(f"generated password: {generated_password}")
    next_steps = _site_create_next_steps(domain, flavor)
    for step in next_steps:
        lines.append(f"next: {step}")
    return _render_summary(heading, lines)


def _add_parser(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
    name: str,
    *,
    help: str,
    description: str | None = None,
    epilog: str | None = None,
) -> argparse.ArgumentParser:
    return subparsers.add_parser(
        name,
        help=help,
        description=description or help,
        epilog=epilog,
        formatter_class=WpfyHelpFormatter,
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="wpfy",
        description="Docker-first CLI for WordPress and server administration.",
        epilog=(
            "Examples:\n"
            "  wpfy run example.com --wp\n"
            "  wpfy backup example.com --list\n"
            "  wpfy config example.com\n"
            "  wpfy stack install --nginx --php --mysql\n"
            "  wpfy site status example.com\n"
        ),
        formatter_class=WpfyHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"wpfy {__version__}")
    subparsers = parser.add_subparsers(dest="command")

    add_site_parser(subparsers)
    add_run_parser(subparsers)
    add_backup_parser(subparsers)
    add_backup_prune_parser(subparsers)
    add_backup_remote_parser(subparsers)
    add_backup_edge_parser(subparsers)
    add_backup_storage_parser(subparsers)
    add_backup_schedule_parser(subparsers)
    add_cron_parser(subparsers)
    add_smtp_parser(subparsers)
    add_dns_parser(subparsers)
    add_restore_parser(subparsers)
    add_restore_edge_parser(subparsers)
    add_rm_parser(subparsers)
    add_wp_parser(subparsers)
    add_version_parser(subparsers)
    add_compose_parser(subparsers)
    add_up_parser(subparsers)
    add_down_parser(subparsers)
    add_exec_parser(subparsers)
    add_cp_parser(subparsers)
    add_pull_parser(subparsers)
    add_config_parser(subparsers)
    add_edit_parser(subparsers)
    add_refresh_parser(subparsers)
    add_healthcheck_parser(subparsers)
    add_motd_parser(subparsers)
    add_utility_parser(subparsers)
    add_stack_parser(subparsers)
    add_sftp_parser(subparsers)
    add_clean_parser(subparsers)
    add_info_parser(subparsers)
    add_log_parser(subparsers)
    add_secure_parser(subparsers)
    add_maintenance_parser(subparsers)
    add_update_parser(subparsers)
    add_debug_parser(subparsers)

    return parser


def add_info_parser(subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    parser = _add_parser(
        subparsers,
        "info",
        help="Show aggregate or per-site configuration details.",
    )
    parser.add_argument("domain", nargs="?")
    parser.add_argument("--nginx", action="store_true")
    parser.add_argument("--php", action="store_true")
    parser.add_argument("--mysql", action="store_true")
    parser.set_defaults(handler=handle_info)


_SECRET_PATTERNS = (
    "PASSWORD", "SECRET", "SALT", "KEY", "TOKEN", "CREDENTIAL",
    "AUTH_KEY", "SECURE_AUTH_KEY", "LOGGED_IN_KEY", "NONCE_KEY",
    "AUTH_SALT", "SECURE_AUTH_SALT", "LOGGED_IN_SALT", "NONCE_SALT",
)


def _sanitize_env(env: dict[str, str]) -> dict[str, str]:
    sanitized = {}
    for key, value in env.items():
        if any(pat in key.upper() for pat in _SECRET_PATTERNS):
            sanitized[key] = "***REDACTED***"
        else:
            sanitized[key] = value
    return sanitized


def _git_config_value(name: str) -> str | None:
    proc = subprocess.run(["git", "config", "--get", name], check=False, capture_output=True, text=True)
    if proc.returncode != 0:
        return None
    value = proc.stdout.strip()
    return value or None


def _normalize_wp_user(value: str | None) -> str:
    candidate = (value or "").strip().lower()
    candidate = re.sub(r"[^a-z0-9_.@-]+", "-", candidate)
    candidate = candidate.strip("-._")
    return candidate or "admin"


def _default_wp_email(domain: str) -> str:
    git_email = _git_config_value("user.email")
    return git_email if git_email else f"admin@{domain}"


def _prompt_or_default(prompt: str, default: str, secret: bool = False) -> str:
    suffix = f" [{default}]" if default else ""
    if secret:
        value = getpass.getpass(f"{prompt}{suffix}: ")
    else:
        value = input(f"{prompt}{suffix}: ")
    return value.strip() or default


def _resolve_wp_admin_credentials(args: argparse.Namespace, domain: str) -> site_lifecycle.WordPressCredentials:
    default_user = _normalize_wp_user(_git_config_value("user.name"))
    default_email = _default_wp_email(domain)
    user = getattr(args, "wp_user", None)
    email = getattr(args, "wp_email", None)
    password = getattr(args, "wp_password", None)
    generated = False

    if sys.stdin.isatty():
        if not user:
            user = _prompt_or_default("WordPress admin user", default_user)
        if not email:
            email = _prompt_or_default("WordPress admin email", default_email)
        if password is None:
            password = getpass.getpass("WordPress admin password [leave blank to generate]: ")
            if not password:
                password = generated_secret()
                generated = True
    else:
        user = user or default_user
        email = email or default_email
        if password is None:
            password = generated_secret()
            generated = True

    return site_lifecycle.WordPressCredentials(
        user=_normalize_wp_user(user),
        email=email.strip(),
        password=password,
        password_generated=generated,
    )


def _site_is_running(domain: str) -> bool:
    proc = compose_command(domain, "ps")
    return proc.returncode == 0 and any(line.strip() for line in proc.stdout.splitlines()[1:])


def _nginx_info(domain: str) -> str:
    project = domain_to_project(domain)
    lines = [f"nginx service ({project}-web):"]
    compose_file = compose_path(domain)
    if compose_file.exists():
        compose_text = compose_file.read_text(encoding="utf-8")
        in_web = False
        web_block = []
        for line in compose_text.splitlines():
            if line.strip().startswith("web:"):
                in_web = True
            if in_web:
                web_block.append(line)
                stripped = line.strip()
                if stripped and not stripped.startswith("#") and not stripped.startswith("  ") and not stripped.startswith("\t"):
                    if not stripped.startswith(" "):
                        break
        if web_block:
            lines.append("  compose.yaml web service:")
            for l in web_block[:40]:
                lines.append("    " + l)
    nginx_conf = nginx_conf_path(domain)
    if nginx_conf.exists():
        lines.append(f"\n  mounted nginx conf ({nginx_conf}):")
        for l in nginx_conf.read_text(encoding="utf-8").splitlines():
            lines.append("    " + l)
    else:
        lines.append("\n  nginx conf: not found")
    return "\n".join(lines)


def _php_info(domain: str) -> str:
    project = domain_to_project(domain)
    lines = [f"php service ({project}-app):"]
    if not _site_is_running(domain):
        return "\n".join(lines) + "\n  status: stopped (run 'wpfy site create' or start runtime to query live config)"
    proc = compose_command(domain, "exec", "-T", "app", "php", "-m")
    if proc.returncode == 0:
        lines.append("  loaded modules:")
        for line in proc.stdout.splitlines():
            lines.append("    " + line)
    else:
        err = proc.stderr.strip() or proc.stdout.strip() or "docker compose exec failed"
        lines.append(f"  query failed: {err}")
    return "\n".join(lines)


def _mysql_info(domain: str) -> str:
    project = domain_to_project(domain)
    lines = [f"mysql service ({project}-db):"]
    if not _site_is_running(domain):
        return "\n".join(lines) + "\n  status: stopped (run 'wpfy site create' or start runtime to query live config)"
    proc = compose_command(
        domain, "exec", "-T", "db", "mariadb",
        "-e", "SHOW VARIABLES WHERE Variable_name IN ('version','max_connections','innodb_buffer_pool_size','datadir')"
    )
    if proc.returncode == 0:
        lines.append("  config variables:")
        for line in proc.stdout.splitlines():
            lines.append("    " + line)
    else:
        err = proc.stderr.strip() or proc.stdout.strip() or "docker compose exec failed"
        lines.append(f"  query failed: {err}")
    return "\n".join(lines)


def handle_info(args: argparse.Namespace) -> CommandResult:
    domain = getattr(args, "domain", None)
    want_nginx = getattr(args, "nginx", False)
    want_php = getattr(args, "php", False)
    want_mysql = getattr(args, "mysql", False)

    if not domain and not (want_nginx or want_php or want_mysql):
        lines = [_section("wpfy aggregate info")]
        facts = operational_inspection.aggregate_info()
        lines.append(f"managed sites: {len(facts.sites)}")
        if facts.sites:
            lines.append("sites:")
            for s in facts.sites:
                lines.append(
                    f"  - {s.get('domain','?')}\t{s.get('flavor','?')}\t"
                    f"ssl={_enabled_text(s.get('ssl_enabled', False))}\t"
                    f"cache={s.get('cache_type', 'basic')}"
                )
        else:
            lines.append("sites: none")
        lines.append(f"traefik: {facts.traefik_message}")
        lines.append(f"docker version: {facts.docker_version}")

        return CommandResult("\n".join(lines))

    if (want_nginx or want_php or want_mysql) and not domain:
        return CommandResult("--nginx/--php/--mysql requires a domain argument", exit_code=2)

    if want_nginx:
        if not site_exists(domain):
            return CommandResult(f"site not found: {domain}", exit_code=2)
        return CommandResult(_nginx_info(domain))

    if want_php:
        if not site_exists(domain):
            return CommandResult(f"site not found: {domain}", exit_code=2)
        return CommandResult(_php_info(domain))

    if want_mysql:
        if not site_exists(domain):
            return CommandResult(f"site not found: {domain}", exit_code=2)
        return CommandResult(_mysql_info(domain))

    if not domain:
        return CommandResult("site name required", exit_code=2)

    if not site_exists(domain):
        return CommandResult(f"site not found: {domain}", exit_code=2)

    lines = [f"=== site info: {domain} ==="]

    meta = registry.get_site(domain)
    if meta:
        lines.append("registry:")
        for k, v in sorted(meta.items()):
            lines.append(f"  {k}={v}")
    else:
        lines.append("registry: no entry")

    cp = compose_path(domain)
    if cp.exists():
        lines.append(f"\ncompose.yaml ({cp}):")
        for l in cp.read_text(encoding="utf-8").splitlines():
            lines.append("  " + l)
    else:
        lines.append("\ncompose.yaml: not found")

    ep = env_path(domain)
    if ep.exists():
        raw_env = read_env(ep)
        env = _sanitize_env(raw_env)
        lines.append(f"\n.env ({ep}) — secrets sanitized:")
        for k, v in sorted(env.items()):
            lines.append(f"  {k}={v}")
    else:
        lines.append("\n.env: not found")

    return CommandResult("\n".join(lines))


def add_clean_parser(subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    parser = _add_parser(
        subparsers,
        "clean",
        help="Clear cached site and runtime data.",
    )
    parser.add_argument("domain", nargs="?", help="specific site domain (default: all sites)")
    parser.add_argument("--redis", action="store_true", help="clear Redis cache (FLUSHALL)")
    parser.add_argument("--opcache", action="store_true", help="reset PHP OPcache (kill -USR2)")
    parser.add_argument("--all", action="store_true", help="clear all cache types")
    parser.set_defaults(handler=handle_clean)


def handle_clean(args: argparse.Namespace) -> CommandResult:
    from .site_layout import compose_command as _compose_cmd, site_exists, list_sites

    domain = getattr(args, "domain", None)
    clear_redis = getattr(args, "redis", False)
    clear_opcache = getattr(args, "opcache", False)
    clear_all = getattr(args, "all", False)

    clear_nginx = not clear_redis and not clear_opcache and not clear_all

    if clear_all:
        clear_nginx = True
        clear_redis = True
        clear_opcache = True

    messages: list[str] = []
    errors: list[str] = []

    if domain:
        sites = [{"domain": domain}]
    else:
        sites = list_sites()

    no_sites_found = not domain and not sites

    for site in sites:
        site_domain = site["domain"] if isinstance(site, dict) else site
        if not site_exists(site_domain):
            messages.append(f"[{site_domain}] skipped: site not found")
            continue

        if clear_nginx:
            _clear_nginx_cache(site_domain, messages, errors)

        if clear_redis:
            _clear_redis_cache(site_domain, messages, errors)

        if clear_opcache:
            _clear_opcache(site_domain, messages, errors)

    lines = [_section("cache clear")]
    if no_sites_found:
        lines.append("no managed sites found")
    elif messages:
        lines.extend(messages)
    else:
        lines.append("nothing cleared")
    if errors:
        lines.append("errors:")
        lines.extend(f"  {error}" for error in errors)
    return CommandResult("\n".join(lines))


def _clear_nginx_cache(domain: str, messages: list[str], errors: list[str]) -> None:
    from .site_layout import compose_command as _compose_cmd
    cache_dirs = ["/var/cache/nginx/fastcgi", "/var/cache/nginx/proxy", "/var/cache/nginx/uwsgi"]
    cleared_any = False
    for cache_dir in cache_dirs:
        proc = _compose_cmd(domain, "exec", "-T", "web", "sh", "-lc", f"rm -rf {cache_dir}/* 2>/dev/null || true")
        if proc.returncode == 0:
            cleared_any = True
    if cleared_any:
        messages.append(f"[{domain}] nginx cache cleared")
    else:
        errors.append(f"[{domain}] nginx cache: docker exec failed")


def _clear_redis_cache(domain: str, messages: list[str], errors: list[str]) -> None:
    from .site_layout import compose_command as _compose_cmd, site_info
    try:
        info = site_info(domain)
    except (FileNotFoundError, ValueError):
        messages.append(f"[{domain}] redis: site not found")
        return
    if info.get("redis") != "1":
        messages.append(f"[{domain}] redis: not enabled (skipped)")
        return
    proc = _compose_cmd(domain, "exec", "-T", "redis", "redis-cli", "FLUSHALL")
    if proc.returncode == 0:
        messages.append(f"[{domain}] redis cache flushed")
    else:
        errors.append(f"[{domain}] redis: exec failed (site may be stopped)")


def _clear_opcache(domain: str, messages: list[str], errors: list[str]) -> None:
    from .site_layout import compose_command as _compose_cmd
    proc = _compose_cmd(domain, "exec", "-T", "app", "sh", "-lc", "kill -USR2 1")
    if proc.returncode == 0:
        messages.append(f"[{domain}] opcache reset")
    else:
        errors.append(f"[{domain}] opcache: exec failed (site may be stopped)")


def add_secure_parser(subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    parser = _add_parser(
        subparsers,
        "secure",
        help="Audit site and container hardening.",
    )
    parser.add_argument("domain", nargs="?", help="site domain to audit (omit with --all for all sites)")
    parser.add_argument("--all", action="store_true", help="audit all managed sites")
    parser.set_defaults(handler=handle_secure)


def handle_secure(args: argparse.Namespace) -> CommandResult:
    domain: str | None = getattr(args, "domain", None)
    all_sites: bool = getattr(args, "all", False)

    if not domain and not all_sites:
        return CommandResult("secure: specify a domain or use --all", exit_code=2)

    sites_to_check: list[str] = []
    if all_sites:
        sites_to_check = [s["domain"] for s in list_sites()]
    elif domain:
        if not site_exists(domain):
            return CommandResult(f"site not found: {domain}", exit_code=2)
        sites_to_check = [domain]

    if not sites_to_check:
        return CommandResult("no sites to audit")

    has_fail = False
    lines: list[str] = []
    for d in sites_to_check:
        lines.append(f"\n=== audit: {d} ===")
        for check in operational_inspection.security_checks(d):
            lines.append(f"[{_label(check.ok)}] {check.name}: {check.message}")
            if check.ok is False:
                has_fail = True

    lines.append(f"\n=== secure summary ===")
    if has_fail:
        lines.append("result: FAIL")
    else:
        lines.append("result: PASS")

    return CommandResult("\n".join(lines), exit_code=1 if has_fail else 0)


def add_maintenance_parser(subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    parser = _add_parser(
        subparsers,
        "maintenance",
        help="Update system packages.",
    )
    parser.add_argument("domain", nargs="?", help="site domain")
    parser.add_argument("--enable", action="store_true", help="enable maintenance mode (stop app container)")
    parser.add_argument("--disable", action="store_true", help="disable maintenance mode (start app container)")
    parser.add_argument("--status", action="store_true", help="show maintenance status")
    parser.set_defaults(handler=handle_maintenance)


def handle_maintenance(args: argparse.Namespace) -> CommandResult:
    domain: str | None = getattr(args, "domain", None)
    enable: bool = getattr(args, "enable", False)
    disable: bool = getattr(args, "disable", False)
    show_status: bool = getattr(args, "status", False)

    if not domain:
        return CommandResult("maintenance: domain is required", exit_code=2)

    if not site_exists(domain):
        return CommandResult(f"site not found: {domain}", exit_code=2)

    if not (enable or disable or show_status):
        show_status = True  # default to status if no flag given

    if show_status:
        meta = registry.get_site(domain)
        maintenance_state = meta.get("maintenance", "disabled") if meta else "disabled"
        return CommandResult(_render_summary("maintenance mode", [f"domain: {domain}", f"state: {maintenance_state}"]))

    if enable:
        compose_command(domain, "stop", "app")
        registry.update_site(domain, {"maintenance": "enabled"})
        return CommandResult(_render_summary("maintenance mode", [f"domain: {domain}", "action: enabled (app container stopped)"]))

    if disable:
        compose_command(domain, "start", "app")
        registry.update_site(domain, {"maintenance": "disabled"})
        return CommandResult(_render_summary("maintenance mode", [f"domain: {domain}", "action: disabled (app container started)"]))

    return CommandResult(_render_summary("maintenance mode", ["no action taken"]))


def add_update_parser(subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    parser = _add_parser(
        subparsers,
        "update",
        help="Check for and install new wpfy releases.",
    )
    parser.add_argument("--check", action="store_true", help="check for available updates (PyPI)")
    parser.add_argument("--force", action="store_true", help="force upgrade wpfy via pip")
    parser.set_defaults(handler=handle_update)


def handle_update(args: argparse.Namespace) -> CommandResult:
    check: bool = getattr(args, "check", False)
    force: bool = getattr(args, "force", False)

    current_version: str
    try:
        current_version = importlib.metadata.version("wpfy")
    except importlib.metadata.PackageNotFoundError:
        current_version = __version__

    if not check and not force:
        return CommandResult(
            _render_summary(
                "wpfy update",
                [
                    f"version: {current_version}",
                    "hint: use --check to see available updates or --force to upgrade",
                ],
            )
        )

    try:
        req = Request(
            "https://pypi.org/pypi/wpfy/json",
            headers={"Accept": "application/json"},
        )
        with urlopen(req, timeout=10) as resp:
            pypi_data = json.loads(resp.read().decode())
        latest = pypi_data["info"]["version"]
    except (URLError, json.JSONDecodeError, KeyError, OSError) as e:
        if force:
            return CommandResult(_render_summary("wpfy update", [f"version: {current_version}", f"FAIL cannot fetch latest version from PyPI: {e}"]), exit_code=2)
        return CommandResult(_render_summary("wpfy update", [f"version: {current_version}", f"PyPI check unavailable: {e}"]))

    if check:
        if current_version == latest:
            return CommandResult(_render_summary("wpfy update", [f"version: {current_version}", "status: up-to-date"]))
        return CommandResult(_render_summary("wpfy update", [f"version: {current_version}", f"status: update available: {latest}", "hint: use --force to upgrade"]))

    if force:
        if current_version == latest:
            return CommandResult(_render_summary("wpfy update", [f"version: {current_version}", "status: already latest"]))
        proc = subprocess.run(
            [sys.executable, "-m", "pip", "install", "--upgrade", "wpfy"],
            check=False, capture_output=True, text=True,
        )
        if proc.returncode != 0:
            err = proc.stderr.strip() or proc.stdout.strip() or "pip install failed"
            return CommandResult(_render_summary("wpfy update", [f"version: {current_version}", f"FAIL upgrade failed: {err}"]), exit_code=proc.returncode)
        return CommandResult(_render_summary("wpfy update", [f"version: {current_version} -> {latest}", "status: upgraded"]))

    return CommandResult(_render_summary("wpfy update", [f"version: {current_version}"]))


def _add_site_create_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("domain")
    parser.add_argument("--html", action="store_true")
    parser.add_argument("--php", choices=SUPPORTED_PHP_VERSIONS, default=DEFAULT_PHP_VERSION)
    parser.add_argument("--mysql", action="store_true")
    parser.add_argument("--wp", action="store_true")
    parser.add_argument("--wpfc", action="store_true")
    parser.add_argument("--wpredis", action="store_true")
    parser.add_argument("--wpsc", action="store_true")
    parser.add_argument("--wprocket", action="store_true")
    parser.add_argument("--wpce", action="store_true")
    parser.add_argument("--wpsubdir", action="store_true")
    parser.add_argument("--wpsubdomain", action="store_true")
    parser.add_argument("-le", "--letsencrypt", nargs="?", const="default")
    parser.add_argument("--dns")
    parser.add_argument(
        "--proxied",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="force proxied (HTTP-01) mode on/off; default auto-detects Cloudflare",
    )
    parser.add_argument("--user", dest="wp_user", help="WordPress administrator username")
    parser.add_argument("--email", dest="wp_email", help="WordPress administrator email")
    parser.add_argument("--pass", dest="wp_password", help="WordPress administrator password")


def add_run_parser(subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    parser = _add_parser(
        subparsers,
        "run",
        help="Create a managed site scaffold and runtime.",
        description="Flat shortcut for `wpfy site create`.",
        epilog=(
            "Examples:\n"
            "  wpfy run example.com --wp\n"
            "  wpfy run example.com --wp -le\n"
            "  wpfy run example.com --html\n"
        ),
    )
    _add_site_create_arguments(parser)
    parser.set_defaults(handler=handle_site_create)


def add_backup_parser(subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    parser = _add_parser(
        subparsers,
        "backup",
        help="Create a site backup archive.",
        description="Flat shortcut for `wpfy site backup`.",
    )
    parser.add_argument("domain")
    parser.add_argument("--list", action="store_true", help="list existing backup archives for the site")
    parser.add_argument("--path", dest="destination_dir", help="copy the verified archive to this directory")
    parser.add_argument("--keep-local", type=int, help="keep newest N local archives after verified backup")
    parser.add_argument("--profile", help="backup storage profile for --s3")
    parser.add_argument(
        "--s3",
        action="store_true",
        help="upload the verified archive to configured S3-compatible storage",
    )
    parser.set_defaults(handler=handle_site_backup)


def add_backup_prune_parser(subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    parser = subparsers.add_parser(
        "backup-prune",
        prog="wpfy backup prune",
        help=argparse.SUPPRESS,
        description="Prune local backup archives.",
        formatter_class=WpfyHelpFormatter,
    )
    parser.add_argument("domain")
    parser.add_argument("--keep", type=int, required=True)
    parser.add_argument("--dry-run", action="store_true")
    parser.set_defaults(handler=handle_backup_prune)


def add_backup_remote_parser(subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    parser = subparsers.add_parser(
        "backup-remote",
        prog="wpfy backup remote",
        help=argparse.SUPPRESS,
        description="List, restore, delete, and prune S3-compatible backup objects.",
        formatter_class=WpfyHelpFormatter,
    )
    remote_subparsers = parser.add_subparsers(dest="remote_command")

    list_parser = remote_subparsers.add_parser("list", help="list remote archives")
    list_parser.add_argument("domain")
    list_parser.add_argument("--profile")
    list_parser.set_defaults(handler=handle_backup_remote)

    restore = remote_subparsers.add_parser("restore", help="restore from a remote archive")
    restore.add_argument("domain")
    key_group = restore.add_mutually_exclusive_group(required=True)
    key_group.add_argument("--key")
    key_group.add_argument("--latest", action="store_true")
    restore.add_argument("--profile")
    restore.set_defaults(handler=handle_backup_remote)

    delete = remote_subparsers.add_parser("delete", help="delete one remote archive")
    delete.add_argument("domain")
    delete.add_argument("--key", required=True)
    delete.add_argument("--profile")
    delete.add_argument("--force", action="store_true")
    delete.set_defaults(handler=handle_backup_remote)

    prune = remote_subparsers.add_parser("prune", help="prune remote archives")
    prune.add_argument("domain")
    prune.add_argument("--keep", type=int, required=True)
    prune.add_argument("--profile")
    prune.add_argument("--force", action="store_true")
    prune.add_argument("--dry-run", action="store_true")
    prune.set_defaults(handler=handle_backup_remote)


def add_backup_edge_parser(subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    parser = subparsers.add_parser(
        "backup-edge",
        prog="wpfy backup edge",
        help=argparse.SUPPRESS,
        description="Back up Traefik config and ACME state.",
        formatter_class=WpfyHelpFormatter,
    )
    parser.add_argument("--path", dest="destination_dir")
    parser.add_argument("--s3", action="store_true")
    parser.add_argument("--profile")
    parser.set_defaults(handler=handle_backup_edge)


def add_backup_storage_parser(subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    parser = subparsers.add_parser(
        "backup-storage",
        prog="wpfy backup storage",
        help=argparse.SUPPRESS,
        description="Configure upload-only S3-compatible backup storage.",
        formatter_class=WpfyHelpFormatter,
    )
    storage_subparsers = parser.add_subparsers(dest="storage_command")

    set_parser = storage_subparsers.add_parser(
        "set",
        help="store default S3-compatible backup storage",
        formatter_class=WpfyHelpFormatter,
    )
    set_parser.add_argument("--endpoint", required=True)
    set_parser.add_argument("--bucket", required=True)
    set_parser.add_argument("--region", required=True)
    set_parser.add_argument("--prefix", default="")
    set_parser.add_argument("--profile")
    set_parser.add_argument("--access-key", required=True)
    set_parser.add_argument("--secret-key-stdin", action="store_true")
    set_parser.set_defaults(handler=handle_backup_storage)

    status = storage_subparsers.add_parser("status", help="show sanitized backup storage status")
    status.add_argument("--profile")
    status.set_defaults(handler=handle_backup_storage)

    test = storage_subparsers.add_parser("test", help="upload a tiny test object")
    test.add_argument("--profile")
    test.set_defaults(handler=handle_backup_storage)

    clear = storage_subparsers.add_parser("clear", help="remove stored backup storage config")
    clear.add_argument("--profile")
    clear.add_argument("--force", action="store_true")
    clear.set_defaults(handler=handle_backup_storage)


def add_backup_schedule_parser(subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    parser = subparsers.add_parser(
        "backup-schedule",
        prog="wpfy backup schedule",
        help=argparse.SUPPRESS,
        description="Configure one systemd timer for recurring all-site backups.",
        formatter_class=WpfyHelpFormatter,
    )
    schedule_subparsers = parser.add_subparsers(dest="schedule_command")

    daily = schedule_subparsers.add_parser("daily", help="run backups every day")
    daily.add_argument("--time", required=True)
    daily.add_argument("--path", dest="destination_dir")
    daily.add_argument("--s3", action="store_true")
    daily.set_defaults(handler=handle_backup_schedule)

    weekly = schedule_subparsers.add_parser("weekly", help="run backups once a week")
    weekly.add_argument("--weekday", required=True)
    weekly.add_argument("--time", required=True)
    weekly.add_argument("--path", dest="destination_dir")
    weekly.add_argument("--s3", action="store_true")
    weekly.set_defaults(handler=handle_backup_schedule)

    status = schedule_subparsers.add_parser("status", help="show backup schedule status")
    status.set_defaults(handler=handle_backup_schedule)

    disable = schedule_subparsers.add_parser("disable", help="disable recurring backups")
    disable.set_defaults(handler=handle_backup_schedule)


def add_cron_parser(subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    parser = _add_parser(
        subparsers,
        "cron",
        help="Run WordPress cron intervals or manage cron timers.",
        description="Run managed WordPress due events and small operator health intervals.",
    )
    cron_subparsers = parser.add_subparsers(dest="cron_command")

    for interval in cron.INTERVALS:
        interval_parser = cron_subparsers.add_parser(interval, help=f"run the {interval} cron interval")
        interval_parser.set_defaults(handler=handle_cron)

    install = cron_subparsers.add_parser("install", help="install systemd timers for all cron intervals")
    install.set_defaults(handler=handle_cron)

    status = cron_subparsers.add_parser("status", help="show cron timer status")
    status.set_defaults(handler=handle_cron)

    disable = cron_subparsers.add_parser("disable", help="disable cron timers")
    disable.set_defaults(handler=handle_cron)


def add_smtp_parser(subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    parser = _add_parser(
        subparsers,
        "smtp",
        help="Configure and test outbound SMTP settings.",
    )
    smtp_subparsers = parser.add_subparsers(dest="smtp_command")

    set_parser = smtp_subparsers.add_parser("set", help="store SMTP settings")
    set_parser.add_argument("--host", required=True)
    set_parser.add_argument("--port", type=int, required=True)
    set_parser.add_argument("--sender", required=True)
    set_parser.add_argument("--username", required=True)
    set_parser.add_argument("--tls", choices=smtp.TLS_MODES, default="starttls")
    set_parser.add_argument("--password-stdin", action="store_true")
    set_parser.set_defaults(handler=handle_smtp)

    status = smtp_subparsers.add_parser("status", help="show sanitized SMTP settings")
    status.set_defaults(handler=handle_smtp)

    test = smtp_subparsers.add_parser("test", help="validate or send a test message")
    test.add_argument("--dry-run", action="store_true", help="validate config without opening a network connection")
    test.add_argument("--to", help="recipient for an explicit SMTP test send")
    test.set_defaults(handler=handle_smtp)

    clear = smtp_subparsers.add_parser("clear", help="remove stored SMTP settings")
    clear.add_argument("--force", action="store_true")
    clear.set_defaults(handler=handle_smtp)


def add_dns_parser(subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    parser = _add_parser(
        subparsers,
        "dns",
        help="Configure DNS provider credentials for wildcard SSL.",
    )
    dns_subparsers = parser.add_subparsers(dest="dns_provider")
    cloudflare = dns_subparsers.add_parser("cloudflare", help="manage Cloudflare DNS credentials")
    cloudflare_subparsers = cloudflare.add_subparsers(dest="dns_command")

    set_parser = cloudflare_subparsers.add_parser("set", help="store Cloudflare token")
    set_parser.add_argument("--token-stdin", action="store_true")
    set_parser.set_defaults(handler=handle_dns)

    status = cloudflare_subparsers.add_parser("status", help="show sanitized Cloudflare DNS status")
    status.set_defaults(handler=handle_dns)

    test = cloudflare_subparsers.add_parser("test", help="verify Cloudflare token")
    test.set_defaults(handler=handle_dns)

    clear = cloudflare_subparsers.add_parser("clear", help="remove Cloudflare DNS token")
    clear.add_argument("--force", action="store_true")
    clear.set_defaults(handler=handle_dns)


def add_restore_parser(subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    parser = _add_parser(
        subparsers,
        "restore",
        help="Restore a site from a backup archive.",
        description="Flat shortcut for `wpfy site restore`.",
    )
    parser.add_argument("domain")
    parser.add_argument("backup", nargs="?")
    parser.add_argument("--list", action="store_true", help="list existing backup archives for the site")
    parser.add_argument("--latest", action="store_true", help="restore newest local archive explicitly")
    parser.set_defaults(handler=handle_site_restore)


def add_restore_edge_parser(subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    parser = subparsers.add_parser(
        "restore-edge",
        prog="wpfy restore edge",
        help=argparse.SUPPRESS,
        description="Restore Traefik config and ACME state.",
        formatter_class=WpfyHelpFormatter,
    )
    parser.add_argument("archive")
    parser.add_argument("--force", action="store_true")
    parser.set_defaults(handler=handle_restore_edge)


def add_rm_parser(subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    parser = _add_parser(
        subparsers,
        "rm",
        help="Remove a managed site and its runtime resources.",
        description="Flat shortcut for `wpfy site delete`.",
    )
    parser.add_argument("domain", nargs="?")
    parser.add_argument("--force", action="store_true", help="skip confirmation prompt")
    parser.set_defaults(handler=make_site_handler("delete"))


def add_wp_parser(subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    parser = _add_parser(
        subparsers,
        "wp",
        help="Run wp-cli inside the site's container.",
        description="Flat shortcut for `wpfy site wp`.",
    )
    parser.add_argument("domain")
    parser.add_argument("wp_args", nargs=argparse.REMAINDER)
    parser.set_defaults(handler=handle_site_wp)


def add_version_parser(subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    parser = _add_parser(
        subparsers,
        "version",
        help="Print the installed wpfy version.",
    )
    parser.set_defaults(handler=handle_version)


def handle_version(args: argparse.Namespace) -> CommandResult:
    return CommandResult(f"wpfy {__version__}")


ALLOWED_RUNTIME_SERVICES: Final = ("app", "web", "db", "redis", "wpcli", "sftp")
DANGEROUS_COPY_PATHS: Final = ("/", ".", "..", "/etc", "/var")


def _require_existing_site(domain: str) -> CommandResult | None:
    try:
        validate_domain(domain)
    except ValueError as exc:
        return CommandResult(str(exc), exit_code=2)
    if not site_exists(domain):
        return CommandResult(f"site not found: {domain}", exit_code=2)
    return None


def _compose_output(proc: subprocess.CompletedProcess[str]) -> str:
    stdout = proc.stdout.strip()
    if stdout:
        return stdout
    return proc.stderr.strip()


def _compose_result(proc: subprocess.CompletedProcess[str]) -> CommandResult:
    return CommandResult(_compose_output(proc), exit_code=proc.returncode)


def add_compose_parser(subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    parser = _add_parser(
        subparsers,
        "compose",
        help="Run Docker Compose for one managed site.",
        description="Canonical flat escape hatch for per-site Docker Compose operations.",
        epilog=(
            "Examples:\n"
            "  wpfy compose example.com -- ps\n"
            "  wpfy compose example.com -- logs --tail 100\n"
            "  wpfy compose example.com -- config\n"
        ),
    )
    parser.add_argument("domain")
    parser.add_argument("compose_args", nargs=argparse.REMAINDER)
    parser.set_defaults(handler=handle_compose)


def handle_compose(args: argparse.Namespace) -> CommandResult:
    site_error = _require_existing_site(args.domain)
    if site_error:
        return site_error
    compose_args = list(args.compose_args or [])
    if not compose_args:
        return CommandResult("compose arguments required after --", exit_code=2)
    return _compose_result(compose_command(args.domain, *compose_args))


def add_up_parser(subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    parser = _add_parser(
        subparsers,
        "up",
        help="Start one managed site's runtime.",
    )
    parser.add_argument("domain")
    parser.set_defaults(handler=handle_up)


def handle_up(args: argparse.Namespace) -> CommandResult:
    site_error = _require_existing_site(args.domain)
    if site_error:
        return site_error
    result = start_site_runtime(args.domain)
    return CommandResult(
        _render_summary("site up", [f"domain: {args.domain}", _step_line("runtime", result)]),
        exit_code=result.exit_code,
    )


def add_down_parser(subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    parser = _add_parser(
        subparsers,
        "down",
        help="Stop one managed site's runtime.",
    )
    parser.add_argument("domain")
    parser.add_argument("--volumes", action="store_true", help="also remove Docker volumes")
    parser.set_defaults(handler=handle_down)


def handle_down(args: argparse.Namespace) -> CommandResult:
    site_error = _require_existing_site(args.domain)
    if site_error:
        return site_error
    remove_volumes = bool(getattr(args, "volumes", False))
    result = stop_site_runtime(args.domain, remove_volumes=remove_volumes)
    return CommandResult(
        _render_summary(
            "site down",
            [
                f"domain: {args.domain}",
                f"volumes: {'removed' if remove_volumes else 'kept'}",
                _step_line("runtime", result),
            ],
        ),
        exit_code=result.exit_code,
    )


def add_exec_parser(subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    parser = _add_parser(
        subparsers,
        "exec",
        help="Run a command in one site's Compose service.",
        epilog=(
            "Examples:\n"
            "  wpfy exec example.com -- php -v\n"
            "  wpfy exec example.com web -- nginx -v\n"
        ),
    )
    parser.add_argument("domain")
    parser.add_argument("service", nargs="?")
    parser.add_argument("exec_args", nargs=argparse.REMAINDER)
    parser.set_defaults(handler=handle_exec)


def handle_exec(args: argparse.Namespace) -> CommandResult:
    site_error = _require_existing_site(args.domain)
    if site_error:
        return site_error
    service = args.service or "app"
    if service not in ALLOWED_RUNTIME_SERVICES:
        return CommandResult(f"invalid service: {service}", exit_code=2)
    exec_args = list(args.exec_args or [])
    if not exec_args or (len(exec_args) == 1 and exec_args[0] in ALLOWED_RUNTIME_SERVICES):
        return CommandResult("exec command required after --", exit_code=2)
    return _compose_result(compose_command(args.domain, "exec", service, *exec_args))


def add_cp_parser(subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    parser = _add_parser(
        subparsers,
        "cp",
        help="Copy a file into or out of one site's Compose services.",
    )
    parser.add_argument("domain")
    parser.add_argument("source")
    parser.add_argument("destination")
    parser.set_defaults(handler=handle_cp)


def _dangerous_copy_path(path: str) -> bool:
    return ":" not in path and path in DANGEROUS_COPY_PATHS


def handle_cp(args: argparse.Namespace) -> CommandResult:
    site_error = _require_existing_site(args.domain)
    if site_error:
        return site_error
    if _dangerous_copy_path(args.source) or _dangerous_copy_path(args.destination):
        return CommandResult("cp source/destination is too broad", exit_code=2)
    return _compose_result(compose_command(args.domain, "cp", args.source, args.destination))


def add_pull_parser(subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    parser = _add_parser(
        subparsers,
        "pull",
        help="Pull images for one managed site.",
    )
    parser.add_argument("domain")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--all", action="store_true", help="pull all services for this site")
    group.add_argument("--service", help="pull one service image")
    parser.set_defaults(handler=handle_pull)


def handle_pull(args: argparse.Namespace) -> CommandResult:
    site_error = _require_existing_site(args.domain)
    if site_error:
        return site_error
    service = getattr(args, "service", None)
    if service:
        if service not in ALLOWED_RUNTIME_SERVICES:
            return CommandResult(f"invalid service: {service}", exit_code=2)
        return _compose_result(compose_command(args.domain, "pull", service))
    return _compose_result(compose_command(args.domain, "pull"))


def _site_definition_from_env(domain: str) -> tuple[SiteDefinition | None, CommandResult | None]:
    config_path = env_path(domain)
    if not config_path.exists():
        return None, CommandResult(f"config not found: {config_path}", exit_code=2)
    try:
        definition = SiteDefinition.from_env(domain, read_env(config_path))
    except ValueError as exc:
        return None, CommandResult(f"config invalid: {exc}", exit_code=2)
    if definition.domain.lower() != domain.lower():
        return None, CommandResult(
            f"config domain mismatch: requested {domain}, found {definition.domain}",
            exit_code=2,
        )
    return definition, None


def _refresh_site_scaffold(domain: str) -> tuple[list[str], CommandResult | None]:
    definition, error = _site_definition_from_env(domain)
    if error:
        return [], error
    if definition is None:
        return [], CommandResult("config could not be loaded", exit_code=2)
    try:
        return ensure_site_scaffold(definition), None
    except ValueError as exc:
        return [], CommandResult(str(exc), exit_code=2)


def _site_update_command_result(
    domain: str,
    request: site_lifecycle.UpdateSiteRequest,
    *,
    title: str = "site updated",
) -> CommandResult:
    try:
        result = site_lifecycle.update_site(request)
    except site_lifecycle.SiteLifecycleError as exc:
        if exc.preflight:
            return CommandResult(
                _render_summary(
                    "ssl preflight",
                    [
                        f"domain: {domain}",
                        "status: failed",
                        f"details: {exc}",
                        "next: no certificate was requested and no changes were applied",
                    ],
                ),
                exit_code=exc.exit_code,
            )
        return CommandResult(str(exc), exit_code=exc.exit_code)

    if result.changes:
        change_summary = f"applied ({'; '.join(result.changes)})"
    else:
        change_summary = "no changes detected"

    lines = [
        _section(title),
        f"domain: {domain}",
        f"changes: {change_summary}",
        f"scaffold: {_site_count_summary(list(result.touched))}",
    ]
    if result.preflight_message:
        lines.append(f"preflight: {result.preflight_message}")
    if result.password_summary:
        lines.append(f"password: {result.password_summary}")
    lines.append(_step_line("runtime", result.runtime))
    return CommandResult("\n".join(lines), exit_code=result.exit_code)


def add_config_parser(subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    parser = _add_parser(
        subparsers,
        "config",
        help="Inspect or safely update one site's config.",
        description="Show sanitized site config or apply controlled updates through the site lifecycle.",
    )
    parser.add_argument("domain")
    parser.add_argument("--php", choices=SUPPORTED_PHP_VERSIONS)
    parser.add_argument("--wpfc", action="store_true")
    parser.add_argument("--wpredis", action="store_true")
    parser.add_argument("--wpsubdir", action="store_true")
    parser.add_argument("--wpsubdomain", action="store_true")
    parser.add_argument("-le", "--letsencrypt", nargs="?", const="default", default=None)
    parser.add_argument("--dns")
    parser.add_argument(
        "--proxied",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="force proxied mode on/off; default keeps the current setting",
    )
    password_group = parser.add_mutually_exclusive_group()
    password_group.add_argument("--password", action="store_true", help="prompt for a new WordPress admin password")
    password_group.add_argument(
        "--password-stdin",
        action="store_true",
        help="read one WordPress admin password from stdin",
    )
    parser.set_defaults(handler=handle_config)


def _config_password(args: argparse.Namespace) -> tuple[str | None, CommandResult | None]:
    if getattr(args, "password_stdin", False):
        password = sys.stdin.readline().rstrip("\r\n")
        if not password:
            return None, CommandResult("password required on stdin", exit_code=2)
        return password, None
    if getattr(args, "password", False):
        if not sys.stdin.isatty():
            return None, CommandResult("password prompt requires a TTY; use --password-stdin for scripts", exit_code=2)
        password = getpass.getpass("WordPress admin password: ")
        if not password:
            return None, CommandResult("password cannot be empty", exit_code=2)
        return password, None
    return None, None


def _has_config_mutation(args: argparse.Namespace) -> bool:
    return any((
        args.php is not None,
        args.wpfc,
        args.wpredis,
        args.wpsubdir,
        args.wpsubdomain,
        args.letsencrypt is not None,
        args.proxied is not None,
        args.password,
        args.password_stdin,
    ))


def handle_config(args: argparse.Namespace) -> CommandResult:
    site_error = _require_existing_site(args.domain)
    if site_error:
        return site_error

    if not _has_config_mutation(args):
        definition, error = _site_definition_from_env(args.domain)
        if error:
            return error
        if definition is None:
            return CommandResult("config could not be loaded", exit_code=2)
        values = read_env(env_path(args.domain))
        return CommandResult(
            _render_summary(
                "site config",
                [
                    f"domain: {args.domain}",
                    f"flavor: {definition.flavor}",
                    f"php: {definition.php_version}",
                    f"mysql: {_enabled_text(definition.use_mysql)}",
                    f"redis: {_enabled_text(definition.use_redis)}",
                    f"ssl: {_enabled_text(definition.ssl_enabled)}",
                    f"proxied: {_enabled_text(definition.proxied)}",
                    f"sftp: {_enabled_text(bool(definition.sftp_password))}",
                    f"database password: {'configured' if values.get('DB_PASSWORD') else 'missing'}",
                    f"sftp password: {'configured' if definition.sftp_password else 'missing'}",
                    f"env: {env_path(args.domain)}",
                    f"compose: {compose_path(args.domain)}",
                ],
            )
        )

    password, password_error = _config_password(args)
    if password_error:
        return password_error
    request = site_lifecycle.UpdateSiteRequest(
        domain=args.domain,
        php_version=args.php,
        wpfc=args.wpfc,
        wpredis=args.wpredis,
        wpsubdir=args.wpsubdir,
        wpsubdomain=args.wpsubdomain,
        letsencrypt=args.letsencrypt,
        dns_provider=getattr(args, "dns", None),
        proxied_override=args.proxied,
        password=password,
    )
    return _site_update_command_result(args.domain, request)


def add_edit_parser(subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    parser = _add_parser(
        subparsers,
        "edit",
        help="Open one site's authoritative config file safely.",
    )
    parser.add_argument("domain")
    parser.add_argument("--print-path", action="store_true", help="print the .env path without opening it")
    parser.set_defaults(handler=handle_edit)


def handle_edit(args: argparse.Namespace) -> CommandResult:
    site_error = _require_existing_site(args.domain)
    if site_error:
        return site_error

    config_path = env_path(args.domain)
    if args.print_path:
        return CommandResult(str(config_path))
    if not config_path.exists():
        return CommandResult(f"config not found: {config_path}", exit_code=2)
    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        return CommandResult("edit requires an interactive TTY", exit_code=2)

    editor = os.environ.get("VISUAL") or os.environ.get("EDITOR")
    if not editor:
        return CommandResult("edit requires EDITOR or VISUAL", exit_code=2)

    backup_path = config_path.with_name(f"{config_path.name}.bak-{datetime.now().strftime('%Y%m%d-%H%M%S')}")
    shutil.copy2(config_path, backup_path)
    proc = subprocess.run([*shlex.split(editor), str(config_path)], check=False)
    if proc.returncode != 0:
        return CommandResult(
            _render_summary(
                "site edit",
                [
                    f"domain: {args.domain}",
                    "config: editor failed",
                    f"backup: {backup_path}",
                    "refresh: skipped",
                ],
            ),
            exit_code=proc.returncode or 1,
        )

    touched, error = _refresh_site_scaffold(args.domain)
    if error:
        return error
    return CommandResult(
        _render_summary(
            "site edit",
            [
                f"domain: {args.domain}",
                "config: opened",
                f"backup: {backup_path}",
                f"refresh: {_site_count_summary(touched)}",
            ],
        )
    )


def add_refresh_parser(subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    parser = _add_parser(
        subparsers,
        "refresh",
        help="Regenerate site scaffold files from authoritative config.",
    )
    parser.add_argument("target")
    parser.add_argument("--restart", action="store_true", help="start runtime after refreshing")
    parser.set_defaults(handler=handle_refresh)


def _refresh_one(domain: str, *, restart: bool) -> CommandResult:
    site_error = _require_existing_site(domain)
    if site_error:
        return site_error
    touched, error = _refresh_site_scaffold(domain)
    if error:
        return error
    lines = [
        f"domain: {domain}",
        f"scaffold: {_site_count_summary(touched)}",
    ]
    exit_code = 0
    if restart:
        runtime = start_site_runtime(domain)
        lines.append(_step_line("runtime", runtime))
        exit_code = runtime.exit_code
    else:
        lines.append("runtime: skipped")
    return CommandResult(_render_summary("site refresh", lines), exit_code=exit_code)


def handle_refresh(args: argparse.Namespace) -> CommandResult:
    if args.target != "all":
        return _refresh_one(args.target, restart=args.restart)

    sites = sorted(str(site["domain"]) for site in list_sites() if site.get("domain"))
    if not sites:
        return CommandResult(_render_summary("refresh all", ["no managed sites found"]))
    lines = [_section("refresh all")]
    exit_code = 0
    for domain in sites:
        result = _refresh_one(domain, restart=args.restart)
        if result.exit_code != 0:
            exit_code = result.exit_code or 1
            lines.append(f"{domain}: FAIL {result.message.splitlines()[-1]}")
        else:
            scaffold = next(
                (
                    line.removeprefix("scaffold: ")
                    for line in result.message.splitlines()
                    if line.startswith("scaffold: ")
                ),
                "unchanged",
            )
            lines.append(f"{domain}: OK {scaffold}")
    return CommandResult("\n".join(lines), exit_code=exit_code)


def add_healthcheck_parser(subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    parser = _add_parser(
        subparsers,
        "healthcheck",
        help="Run flat operator health checks.",
        description="Run script-safe health checks for disk, load, system services, and managed sites.",
        epilog=(
            "Examples:\n"
            "  wpfy healthcheck\n"
            "  wpfy healthcheck disk --warn 80 --fail 90\n"
            "  wpfy healthcheck app example.com\n"
            "  wpfy healthcheck app --all-sites\n"
        ),
    )
    health_subparsers = parser.add_subparsers(dest="health_target")

    all_parser = _add_parser(health_subparsers, "all", help="Run all operator health checks.")
    all_parser.set_defaults(health_target="all")

    system_parser = _add_parser(health_subparsers, "system", help="Check Docker, Traefik, and registry state.")
    system_parser.set_defaults(health_target="system")

    disk_parser = _add_parser(health_subparsers, "disk", help="Check host disk usage.")
    disk_parser.add_argument("--path", default="/", help="filesystem path to inspect")
    disk_parser.add_argument("--warn", type=float, default=80.0, help="warning threshold percentage")
    disk_parser.add_argument("--fail", type=float, default=90.0, help="failure threshold percentage")
    disk_parser.set_defaults(health_target="disk")

    load_parser = _add_parser(health_subparsers, "load", help="Check host load average per CPU.")
    load_parser.add_argument("--warn", type=float, default=1.5, help="warning threshold per CPU")
    load_parser.add_argument("--fail", type=float, default=3.0, help="failure threshold per CPU")
    load_parser.set_defaults(health_target="load")

    app_parser = _add_parser(health_subparsers, "app", help="Check one or all managed sites.")
    app_parser.add_argument("domain", nargs="?", help="site domain to check")
    app_parser.add_argument("--all-sites", action="store_true", help="check every managed site")
    app_parser.set_defaults(health_target="app")

    parser.set_defaults(handler=handle_healthcheck, health_target="all")


def _valid_percent_thresholds(warn: float, fail: float) -> bool:
    return 0 < warn < fail <= 100


def _valid_load_thresholds(warn: float, fail: float) -> bool:
    return 0 < warn < fail


def _format_bytes(value: int) -> str:
    size = float(value)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if size < 1024 or unit == "TiB":
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TiB"


def _render_checks(title: str, checks: tuple[operational_inspection.InspectionCheck, ...]) -> tuple[list[str], bool]:
    lines = [_section(title)]
    has_fail = False
    for check in checks:
        lines.append(f"[{_label(check.ok)}] {check.name}: {check.message}")
        if check.ok is False:
            has_fail = True
    return lines, has_fail


def _healthcheck_disk(path: str, warn: float, fail: float) -> CommandResult:
    if not _valid_percent_thresholds(warn, fail):
        return CommandResult("invalid thresholds: require 0 < warn < fail <= 100", exit_code=2)
    try:
        usage = shutil.disk_usage(path)
    except (FileNotFoundError, PermissionError, OSError) as exc:
        return CommandResult(f"[FAIL] disk: {exc}", exit_code=1)
    used_percent = usage.used / usage.total * 100 if usage.total else 0.0
    if used_percent >= fail:
        ok = False
    elif used_percent >= warn:
        ok = None
    else:
        ok = True
    check = operational_inspection.InspectionCheck(
        "disk",
        ok,
        (
            f"{used_percent:.1f}% used at {path}; "
            f"total={_format_bytes(usage.total)} used={_format_bytes(usage.used)} free={_format_bytes(usage.free)}"
        ),
    )
    lines, has_fail = _render_checks("healthcheck disk", (check,))
    return CommandResult("\n".join(lines), exit_code=1 if has_fail else 0)


def _healthcheck_load(warn: float, fail: float) -> CommandResult:
    if not _valid_load_thresholds(warn, fail):
        return CommandResult("invalid thresholds: require 0 < warn < fail", exit_code=2)
    try:
        load1, load5, load15 = os.getloadavg()
    except (AttributeError, OSError):
        check = operational_inspection.InspectionCheck("load", None, "load average unavailable on this platform")
        lines, has_fail = _render_checks("healthcheck load", (check,))
        return CommandResult("\n".join(lines), exit_code=1 if has_fail else 0)
    cpu_count = os.cpu_count() or 1
    per_cpu = load1 / cpu_count
    if per_cpu >= fail:
        ok = False
    elif per_cpu >= warn:
        ok = None
    else:
        ok = True
    check = operational_inspection.InspectionCheck(
        "load",
        ok,
        f"{per_cpu:.2f} per CPU; raw 1m/5m/15m {load1:.2f}/{load5:.2f}/{load15:.2f} on {cpu_count} CPUs",
    )
    lines, has_fail = _render_checks("healthcheck load", (check,))
    return CommandResult("\n".join(lines), exit_code=1 if has_fail else 0)


def _healthcheck_system() -> CommandResult:
    if runtime_skip_requested():
        checks = (operational_inspection.InspectionCheck("runtime", None, "runtime skipped by WPFY_SKIP_RUNTIME=1"),)
    else:
        checks = operational_inspection.system_diagnostics()
    lines, has_fail = _render_checks("healthcheck system", checks)
    return CommandResult("\n".join(lines), exit_code=1 if has_fail else 0)


def _app_health_ok(status: str, bootstrap_ready: bool, runtime_ready: bool) -> bool | None:
    if not bootstrap_ready:
        return False
    if runtime_ready or status == "ready":
        return True
    if status == "down":
        return False
    return None


def _healthcheck_app_domain(domain: str) -> CommandResult:
    site_error = _require_existing_site(domain)
    if site_error:
        return site_error
    health = site_health(domain)
    ok = _app_health_ok(health.status, health.bootstrap_ready, health.runtime_ready)
    line = f"{domain}: {_label(ok)} {health.status} - {health.message}"
    return CommandResult(line, exit_code=1 if ok is False else 0)


def _healthcheck_all_sites() -> CommandResult:
    sites = sorted(str(site["domain"]) for site in list_sites() if site.get("domain"))
    lines = [_section("sites")]
    if not sites:
        lines.append("no managed sites found")
        return CommandResult("\n".join(lines))
    exit_code = 0
    for domain in sites:
        result = _healthcheck_app_domain(domain)
        lines.append(result.message)
        if result.exit_code == 1:
            exit_code = 1
        elif result.exit_code == 2 and exit_code == 0:
            exit_code = 2
    return CommandResult("\n".join(lines), exit_code=exit_code)


def handle_healthcheck(args: argparse.Namespace) -> CommandResult:
    target = getattr(args, "health_target", None) or "all"
    if target == "disk":
        return _healthcheck_disk(args.path, args.warn, args.fail)
    if target == "load":
        return _healthcheck_load(args.warn, args.fail)
    if target == "system":
        return _healthcheck_system()
    if target == "app":
        all_sites = bool(getattr(args, "all_sites", False))
        domain = getattr(args, "domain", None)
        if all_sites and domain:
            return CommandResult("use either a domain or --all-sites, not both", exit_code=2)
        if all_sites:
            return _healthcheck_all_sites()
        if not domain:
            return CommandResult("healthcheck app requires a domain or --all-sites", exit_code=2)
        return _healthcheck_app_domain(domain)
    if target != "all":
        return CommandResult(f"unknown healthcheck target: {target}", exit_code=2)

    results = [
        _healthcheck_disk("/", 80.0, 90.0),
        _healthcheck_load(1.5, 3.0),
        _healthcheck_system(),
        _healthcheck_all_sites(),
    ]
    lines = [_section("healthcheck")]
    exit_code = 0
    for result in results:
        if result.message:
            lines.extend(result.message.splitlines())
        if result.exit_code == 1:
            exit_code = 1
        elif result.exit_code == 2 and exit_code == 0:
            exit_code = 2
    return CommandResult("\n".join(lines), exit_code=exit_code)


def add_motd_parser(subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    parser = _add_parser(
        subparsers,
        "motd",
        help="Print a safe operator login summary.",
    )
    parser.add_argument("--compact", action="store_true", help="print a shorter one-screen summary")
    parser.set_defaults(handler=handle_motd)


def _site_cache_label(site: dict[str, str]) -> str:
    cache = site.get("cache_type")
    if cache:
        return cache
    return "redis" if _enabled_text(site.get("redis", "0")) == "enabled" else "basic"


def _site_ssl_label(site: dict[str, str]) -> str:
    value = site.get("ssl")
    if value is None:
        return _enabled_text(site.get("ssl_enabled", False))
    return _enabled_text(value)


def _motd_warning_count(facts: operational_inspection.AggregateInfo) -> int:
    count = 0
    if facts.docker_version == "unavailable":
        count += 1
    lowered = facts.traefik_message.lower()
    if "unavailable" in lowered or "not running" in lowered or "not installed" in lowered or "error" in lowered:
        count += 1
    return count


def handle_motd(args: argparse.Namespace) -> CommandResult:
    facts = operational_inspection.aggregate_info()
    sites = sorted(facts.sites, key=lambda site: str(site.get("domain", "")))
    warnings = _motd_warning_count(facts)
    if getattr(args, "compact", False):
        return CommandResult(
            f"wpfy {__version__} | docker={facts.docker_version} | "
            f"traefik={facts.traefik_message} | sites={len(sites)} | warnings={warnings}"
        )

    lines = [
        _section("wpfy motd"),
        f"version: {__version__}",
        f"docker: {facts.docker_version}",
        f"traefik: {facts.traefik_message}",
        f"sites: {len(sites)} managed",
        f"warnings: {warnings}",
    ]
    if sites:
        lines.append("")
        lines.append("sites:")
        for site in sites:
            domain = site.get("domain", "?")
            flavor = site.get("flavor", "?")
            lines.append(f"- {domain} {flavor} ssl={_site_ssl_label(site)} cache={_site_cache_label(site)}")
    lines.extend(["", "next:", "- run `wpfy healthcheck all` for full diagnostics"])
    return CommandResult("\n".join(lines))


SAFE_USERNAME_RE: Final = re.compile(r"^[A-Za-z0-9_.@-]+$")
PASSWORD_SYMBOLS: Final = "!#$%&()*+,-./:;<=>?@[]^_{|}~"


def add_utility_parser(subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    parser = _add_parser(
        subparsers,
        "utility",
        help="Generate offline-safe operator values.",
    )
    utility_subparsers = parser.add_subparsers(dest="utility_command")

    password = _add_parser(utility_subparsers, "password", help="Generate a random password.")
    password.add_argument("--length", type=int, default=24)
    password.add_argument("--no-symbols", action="store_true")
    password.set_defaults(handler=handle_utility_password)

    token = _add_parser(utility_subparsers, "token", help="Generate a URL-safe token.")
    token.add_argument("--bytes", type=int, default=32)
    token.set_defaults(handler=handle_utility_token)

    username = _add_parser(utility_subparsers, "username", help="Normalize a safe username.")
    username.add_argument("value")
    username.set_defaults(handler=handle_utility_username)

    uid = _add_parser(utility_subparsers, "uid", help="Show deterministic project name and site UID state.")
    uid.add_argument("domain")
    uid.set_defaults(handler=handle_utility_uid)

    htpasswd = _add_parser(utility_subparsers, "htpasswd", help="Generate a stdlib-compatible htpasswd line.")
    htpasswd.add_argument("--username", required=True)
    htpasswd.add_argument("--password-stdin", action="store_true", help="read one password from stdin")
    htpasswd.set_defaults(handler=handle_utility_htpasswd)


def _generate_password(length: int, include_symbols: bool) -> str:
    groups = [string.ascii_lowercase, string.ascii_uppercase, string.digits]
    if include_symbols:
        groups.append(PASSWORD_SYMBOLS)
    rng = secrets.SystemRandom()
    selected = [secrets.choice(group) for group in groups]
    charset = "".join(groups)
    selected.extend(secrets.choice(charset) for _ in range(length - len(selected)))
    rng.shuffle(selected)
    return "".join(selected)


def handle_utility_password(args: argparse.Namespace) -> CommandResult:
    if not 12 <= args.length <= 128:
        return CommandResult("password length must be between 12 and 128", exit_code=2)
    return CommandResult(_generate_password(args.length, not args.no_symbols))


def handle_utility_token(args: argparse.Namespace) -> CommandResult:
    if not 16 <= args.bytes <= 128:
        return CommandResult("token bytes must be between 16 and 128", exit_code=2)
    return CommandResult(secrets.token_urlsafe(args.bytes))


def handle_utility_username(args: argparse.Namespace) -> CommandResult:
    return CommandResult(_normalize_wp_user(args.value))


def handle_utility_uid(args: argparse.Namespace) -> CommandResult:
    try:
        validate_domain(args.domain)
    except ValueError as exc:
        return CommandResult(str(exc), exit_code=2)
    site_uid = "not allocated"
    if site_exists(args.domain):
        site_uid = read_env(env_path(args.domain)).get("SITE_UID") or "not allocated"
    return CommandResult(
        "\n".join([
            f"domain: {args.domain}",
            f"project: {domain_to_project(args.domain)}",
            f"site_uid: {site_uid}",
        ])
    )


def _safe_htpasswd_username(value: str) -> bool:
    return bool(SAFE_USERNAME_RE.fullmatch(value))


def _htpasswd_sha(password: str) -> str:
    digest = hashlib.sha1(password.encode("utf-8")).digest()
    return "{SHA}" + base64.b64encode(digest).decode("ascii")


def handle_utility_htpasswd(args: argparse.Namespace) -> CommandResult:
    username = args.username.strip()
    if not username or not _safe_htpasswd_username(username):
        return CommandResult("invalid username: use letters, digits, '_', '.', '@', or '-'", exit_code=2)
    generated = not args.password_stdin
    if generated:
        password = _generate_password(24, True)
    else:
        password = sys.stdin.readline().rstrip("\r\n")
        if not password:
            return CommandResult("password required on stdin", exit_code=2)
    htpasswd = f"{username}:{_htpasswd_sha(password)}"
    if generated:
        return CommandResult("\n".join([f"username: {username}", f"password: {password}", f"htpasswd: {htpasswd}"]))
    return CommandResult(f"htpasswd: {htpasswd}")


def add_site_parser(subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    parser = _add_parser(
        subparsers,
        "site",
        help="Create, inspect, update, and remove managed sites.",
        description="Retained grouped namespace for per-site operations, including SSL/status/list/show.",
        epilog=(
            "Examples:\n"
            "  wpfy run example.com --wp\n"
            "  wpfy backup example.com\n"
            "  wpfy site create example.com --wp -le\n"
            "  wpfy site status example.com\n"
            "  wpfy site ssl example.com --status\n"
        ),
    )
    site_subparsers = parser.add_subparsers(dest="site_command")

    create = _add_parser(
        site_subparsers,
        "create",
        help="Create a managed site scaffold and runtime.",
        description="Create a site, bootstrap its filesystem, and optionally provision WordPress.",
        epilog=(
            "Examples:\n"
            "  wpfy site create example.com --wp\n"
            "  wpfy site create example.com --wp -le\n"
            "  wpfy site create example.com --wp --user=admin --email=admin@example.com\n"
        ),
    )
    _add_site_create_arguments(create)
    create.set_defaults(handler=handle_site_create)

    ssl = _add_parser(
        site_subparsers,
        "ssl",
        help="Enable SSL, inspect certificate status, or renew certificates.",
        description="Manage Let’s Encrypt preflight, Traefik labels, renewal, and certificate status.",
        epilog=(
            "Examples:\n"
            "  wpfy site ssl example.com --letsencrypt\n"
            "  wpfy site ssl example.com --status\n"
            "  wpfy site ssl example.com --renew\n"
        ),
    )
    ssl.add_argument("domain")
    ssl.add_argument("-le", "--letsencrypt", nargs="?", const="default")
    ssl.add_argument("--dns")
    ssl.add_argument(
        "--proxied",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="force proxied (HTTP-01) mode on/off; default auto-detects Cloudflare",
    )
    ssl.add_argument("--renew", action="store_true")
    ssl.add_argument("--status", action="store_true")
    ssl.add_argument("--preflight-only", action="store_true")
    ssl.set_defaults(handler=handle_site_ssl)

    backup = _add_parser(
        site_subparsers,
        "backup",
        help="Create a site backup archive.",
    )
    backup.add_argument("domain")
    backup.add_argument("--list", action="store_true", help="list existing backup archives for the site")
    backup.add_argument("--path", dest="destination_dir", help="copy the verified archive to this directory")
    backup.add_argument("--keep-local", type=int, help="keep newest N local archives after verified backup")
    backup.add_argument("--profile", help="backup storage profile for --s3")
    backup.add_argument(
        "--s3",
        action="store_true",
        help="upload the verified archive to configured S3-compatible storage",
    )
    backup.set_defaults(handler=handle_site_backup)

    restore = _add_parser(
        site_subparsers,
        "restore",
        help="Restore a site from a backup archive.",
    )
    restore.add_argument("domain")
    restore.add_argument("backup", nargs="?")
    restore.add_argument("--list", action="store_true", help="list existing backup archives for the site")
    restore.add_argument("--latest", action="store_true", help="restore newest local archive explicitly")
    restore.set_defaults(handler=handle_site_restore)

    wp = _add_parser(
        site_subparsers,
        "wp",
        help="Run wp-cli inside the site's container.",
    )
    wp.add_argument("domain")
    wp.add_argument("wp_args", nargs=argparse.REMAINDER)
    wp.set_defaults(handler=handle_site_wp)

    site_action_names = ("delete", "list", "info", "show", "status")
    for name in site_action_names:
        help_text = {
            "delete": "Remove a managed site and its runtime resources.",
            "list": "List managed sites.",
            "info": "Show site metadata and file paths.",
            "show": "Print the generated compose file.",
            "status": "Show site readiness and runtime health.",
        }[name]
        site_parser = _add_parser(site_subparsers, name, help=help_text)
        if name in {"delete", "info", "show", "status"}:
            site_parser.add_argument("domain", nargs="?")
        if name == "delete":
            site_parser.add_argument("--force", action="store_true", help="skip confirmation prompt")
        if name == "list":
            site_parser.add_argument("--enabled", action="store_true")
            site_parser.add_argument("--disabled", action="store_true")
        site_parser.set_defaults(handler=make_site_handler(name))

    update = _add_parser(
        site_subparsers,
        "update",
        help="Update a site's PHP version, cache flavor, or SSL settings.",
        description="Regenerate a site scaffold after changing PHP, cache, or SSL options.",
    )
    update.add_argument("domain")
    update.add_argument("--php", choices=SUPPORTED_PHP_VERSIONS)
    update.add_argument("--wpfc", action="store_true")
    update.add_argument("--wpredis", action="store_true")
    update.add_argument("-le", "--letsencrypt", nargs="?", const="default", default=None)
    update.add_argument(
        "--proxied",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="force proxied (HTTP-01) mode on/off; default keeps the current setting",
    )
    update.add_argument("--password")
    update.add_argument("--wpsubdir", action="store_true")
    update.add_argument("--wpsubdomain", action="store_true")
    update.add_argument("--dns")
    update.set_defaults(handler=handle_site_update)


def add_stack_parser(subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    parser = _add_parser(
        subparsers,
        "stack",
        help="Install or inspect shared runtime components.",
        description="Retained grouped namespace for shared stack install, lifecycle, and status operations.",
        epilog=(
            "Examples:\n"
            "  wpfy stack install --nginx --php --mysql\n"
            "  wpfy stack install --php 8.3\n"
            "  wpfy stack status\n"
        ),
    )
    stack_subparsers = parser.add_subparsers(dest="stack_command")

    install = _add_parser(
        stack_subparsers,
        "install",
        help="Pull images and start Traefik.",
        description="Pull the Docker images needed by wpfy and start the shared edge proxy.",
        epilog=(
            "Examples:\n"
            "  wpfy stack install --nginx\n"
            "  wpfy stack install --php\n"
            "  wpfy stack install --all\n"
        ),
    )
    install.add_argument("--all", action="store_true")
    install.add_argument("--nginx", action="store_true")
    install.add_argument("--php", nargs="?", const=DEFAULT_PHP_VERSION, choices=SUPPORTED_PHP_VERSIONS)
    install.add_argument("--mysql", action="store_true")
    install.add_argument("--mariadb", action="store_true")
    install.add_argument("--redis", action="store_true")
    install.add_argument("--wpcli", action="store_true")
    install.add_argument("--netdata", action="store_true")
    install.add_argument("--fail2ban", action="store_true")
    install.add_argument("--ufw", action="store_true")
    install.add_argument("--ngxblocker", action="store_true")
    install.add_argument("--nanorc", action="store_true")
    install.add_argument("--dashboard", action="store_true")
    install.add_argument("--extplorer", action="store_true")
    install.add_argument("--phpmyadmin", action="store_true")
    install.add_argument("--adminer", action="store_true")
    install.add_argument("--composer", action="store_true")
    install.add_argument("--mysqltuner", action="store_true")
    install.set_defaults(handler=handle_stack_install)

    for name in ("remove", "purge", "migrate", "upgrade", "status"):
        help_text = {
            "remove": "Stop Traefik and remove the edge proxy container.",
            "purge": "Stop Traefik and remove the Compose project.",
            "migrate": "Report that migration is not implemented in v1.",
            "upgrade": "Pull the latest Traefik image and restart it.",
            "status": "Show stack component status.",
        }[name]
        stack_parser = _add_parser(stack_subparsers, name, help=help_text)
        if name in ("remove", "purge"):
            stack_parser.add_argument("--force", action="store_true")
        handler_map = {
            "remove": handle_stack_remove,
            "purge": handle_stack_purge,
            "migrate": handle_stack_migrate,
            "upgrade": handle_stack_upgrade,
            "status": handle_stack_status,
        }
        stack_parser.set_defaults(handler=handler_map[name])


def add_sftp_parser(subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    parser = _add_parser(
        subparsers,
        "sftp",
        help="Enable or inspect per-site SFTP access.",
    )
    parser.add_argument("domain")
    parser.add_argument("--enable", action="store_true", help="enable SFTP access for the site")
    parser.add_argument("--disable", action="store_true", help="disable SFTP access for the site")
    parser.add_argument("--status", action="store_true", help="show SFTP container status")
    parser.add_argument("--password", help="custom SFTP password (auto-generated if omitted)")
    parser.set_defaults(handler=handle_sftp)


def handle_sftp(args: argparse.Namespace) -> CommandResult:
    domain = args.domain
    if args.enable:
        result = sftp.ensure_sftp_container(domain, password=args.password)
    elif args.disable:
        result = sftp.remove_sftp_container(domain)
    elif args.status:
        result = sftp.sftp_status(domain)
    else:
        result = sftp.sftp_status(domain)
    return CommandResult(result.message, exit_code=result.exit_code)


def add_log_parser(subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    parser = _add_parser(
        subparsers,
        "log",
        help="Inspect or reset service logs.",
    )
    log_subparsers = parser.add_subparsers(dest="log_command")

    log_show = _add_parser(
        log_subparsers,
        "show",
        help="Show recent service logs.",
    )
    log_show.add_argument("domain")
    log_show.add_argument("--nginx", action="store_true")
    log_show.add_argument("--php", action="store_true")
    log_show.add_argument("--mysql", action="store_true")
    log_show.add_argument("-f", "--follow", action="store_true")
    log_show.add_argument("--lines", type=int, default=100)
    log_show.set_defaults(handler=handle_log_show)

    log_reset = _add_parser(
        log_subparsers,
        "reset",
        help="Restart the site containers to clear logs.",
    )
    log_reset.add_argument("domain")
    log_reset.set_defaults(handler=handle_log_reset)

    log_cron = _add_parser(
        log_subparsers,
        "cron",
        help="Show recent wpfy cron log output.",
    )
    log_cron.add_argument("--lines", type=int, default=100)
    log_cron.set_defaults(handler=handle_log_cron)


def handle_log_show(args: argparse.Namespace) -> CommandResult:
    domain = args.domain
    try:
        site_info(domain)
    except (FileNotFoundError, ValueError) as exc:
        return CommandResult(str(exc), exit_code=2)

    compose_file = str(compose_path(domain))
    site_directory = str(site_dir(domain))

    service_filter: list[str] = []
    if args.nginx:
        service_filter.append("web")
    if args.php:
        service_filter.append("app")
    if args.mysql:
        service_filter.append("db")

    cmd = ["docker", "compose", "-f", compose_file, "logs"]
    cmd.extend(["--tail", str(args.lines)])
    if args.follow:
        cmd.append("--follow")
    for svc in service_filter:
        cmd.append(svc)

    if args.follow:
        proc = subprocess.run(cmd, cwd=site_directory, check=False)
        return CommandResult("", exit_code=proc.returncode)

    proc = subprocess.run(cmd, cwd=site_directory, check=False, capture_output=True, text=True)
    output = proc.stdout
    if not output and proc.stderr:
        output = proc.stderr
    return CommandResult(output, exit_code=proc.returncode)


def handle_log_cron(args: argparse.Namespace) -> CommandResult:
    result = cron.read_cron_log(args.lines)
    return CommandResult(result.message, exit_code=result.exit_code)


def handle_log_reset(args: argparse.Namespace) -> CommandResult:
    domain = args.domain
    try:
        site_info(domain)
    except (FileNotFoundError, ValueError) as exc:
        return CommandResult(str(exc), exit_code=2)

    compose_file = str(compose_path(domain))
    site_directory = str(site_dir(domain))

    down_proc = subprocess.run(
        ["docker", "compose", "-f", compose_file, "down"],
        cwd=site_directory, check=False, capture_output=True, text=True,
    )
    if down_proc.returncode != 0:
        err = down_proc.stderr.strip() or down_proc.stdout.strip() or "docker compose down failed"
        return CommandResult(
            _render_summary("log reset", [f"domain: {domain}", f"runtime: FAIL {err}"]),
            exit_code=down_proc.returncode,
        )

    up_proc = subprocess.run(
        ["docker", "compose", "-f", compose_file, "up", "-d"],
        cwd=site_directory, check=False, capture_output=True, text=True,
    )
    if up_proc.returncode != 0:
        err = up_proc.stderr.strip() or up_proc.stdout.strip() or "docker compose up failed"
        lines = [
            _section("log reset"),
            "runtime: OK stopped",
            f"restart: FAIL {err}",
        ]
        return CommandResult("\n".join(lines), exit_code=up_proc.returncode)

    lines = [
        _section("log reset"),
        f"domain: {domain}",
        "runtime: OK stopped",
        "restart: OK started",
    ]
    return CommandResult("\n".join(lines))


def make_site_handler(name: str):
    def handler(args: argparse.Namespace) -> CommandResult:
        domain = getattr(args, "domain", None)
        if name == "list":
            sites = list_sites()
            if not sites:
                return CommandResult(_render_summary("managed sites", ["no managed sites found"]))
            lines = [_section(f"managed sites ({len(sites)})")]
            for site in sites:
                lines.append(
                    f"{site.get('domain', '?')}\t{site.get('flavor', '?')}\t"
                    f"ssl={_enabled_text(site.get('ssl_enabled', site.get('ssl', 'disabled')))}\t"
                    f"cache={site.get('cache_type', 'basic')}"
                )
            return CommandResult("\n".join(lines))

        if name == "info":
            if not domain:
                return CommandResult("site name required", exit_code=2)
            try:
                info = site_info(domain)
            except (FileNotFoundError, ValueError) as exc:
                return CommandResult(str(exc), exit_code=2)
            lines = [
                _section(f"site info: {info['domain']}"),
                f"domain: {info['domain']}",
                f"flavor: {info.get('flavor', 'unknown')}",
                f"path: {info['path']}",
                f"compose: {info['compose']}",
                f"env: {info['env']}",
                f"ssl: {_enabled_text(info.get('ssl', 'disabled'))}",
                f"redis: {_enabled_text(info.get('redis', '0'))}",
            ]
            meta = registry.get_site(domain)
            if meta:
                lines.append("registry:")
                for key, value in sorted(meta.items()):
                    lines.append(f"  {key}: {value}")
            return CommandResult("\n".join(lines))

        if name == "show":
            if not domain:
                return CommandResult("site name required", exit_code=2)
            try:
                info = site_info(domain)
            except (FileNotFoundError, ValueError) as exc:
                return CommandResult(str(exc), exit_code=2)
            compose = Path(info["compose"]).read_text(encoding="utf-8")
            return CommandResult(compose.rstrip())

        if name == "status":
            if not domain:
                return CommandResult("site name required", exit_code=2)
            try:
                info = site_info(domain)
            except (FileNotFoundError, ValueError) as exc:
                return CommandResult(str(exc), exit_code=2)
            health = site_health(domain)
            lines = [
                _section(f"site status: {info['domain']}"),
                f"domain: {info['domain']}",
                f"flavor: {info.get('flavor', 'unknown')}",
                f"path: {info['path']}",
                f"compose: {info['compose']}",
                f"status: {health.status}",
                f"scaffold: {_bool_text(health.scaffold_ready)}",
                f"bootstrap: {_bool_text(health.bootstrap_ready)}",
                f"runtime: {_bool_text(health.runtime_ready)}",
                f"http: {_bool_text(health.http_ready)}",
                f"summary: {health.message}",
            ]
            return CommandResult("\n".join(lines))

        if name == "delete":
            if not domain:
                return CommandResult("site name required", exit_code=2)
            if not site_exists(domain):
                return CommandResult(f"site not found: {domain}", exit_code=2)
            force: bool = getattr(args, "force", False)
            if not force:
                if not sys.stdin.isatty():
                    return CommandResult(f"delete aborted: --force required when stdin is not a TTY", exit_code=2)
                try:
                    answer = input(f"Delete {domain}? [y/N] ")
                except EOFError:
                    return CommandResult(f"delete aborted", exit_code=2)
                if answer.strip().lower() not in ("y", "yes"):
                    return CommandResult(f"delete aborted")
            try:
                backup_result = backup_site(domain)
                stop_result = stop_site_runtime(domain, remove_volumes=True)
                if stop_result.exit_code != 0 and not force:
                    return CommandResult(
                        _render_summary(
                            "site delete",
                            [
                                f"domain: {domain}",
                                _step_line("backup", backup_result),
                                _step_line("runtime", stop_result),
                                "files: kept",
                            ],
                        ),
                        exit_code=stop_result.exit_code,
                    )
                removed = remove_site_scaffold(domain)
            except (FileNotFoundError, ValueError) as exc:
                return CommandResult(str(exc), exit_code=2)
            if removed:
                lines = [
                    _section("site deleted"),
                    f"domain: {domain}",
                    _step_line("backup", backup_result),
                    _step_line("runtime", stop_result),
                    "files: removed",
                ]
                return CommandResult("\n".join(lines))
            return CommandResult(f"site not found: {domain}", exit_code=2)

        if domain:
            return CommandResult(_render_summary(name, [f"domain: {domain}", "result: scaffolded"]))
        return CommandResult(_render_summary(name, ["result: scaffolded"]))

    return handler


def _pull_php_image(php_ver: str) -> tuple[bool, str]:
    image = php_image(php_ver)
    return _pull_image(image)


def _pull_image(image: str) -> tuple[bool, str]:
    proc = subprocess.run(["docker", "pull", image], check=False, capture_output=True, text=True)
    if proc.returncode == 0:
        return True, f"pulled {image}"
    err = (proc.stderr.strip() or proc.stdout.strip() or "pull failed").splitlines()[-1]
    return False, f"error: {err}"


def handle_stack_install(args: argparse.Namespace) -> CommandResult:
    results: list[str] = [_section("stack install")]
    exit_code = 0
    pulled_php_versions: set[str] = set()
    install_all = getattr(args, "all", False)

    if install_all or getattr(args, "nginx", False):
        _progress("Starting shared Traefik edge proxy...")
        result = traefik.start_traefik()
        results.append(_step_line("Traefik", result))
        if result.exit_code != 0:
            exit_code = result.exit_code

    php_ver = getattr(args, "php", None)
    if install_all and not php_ver:
        php_ver = DEFAULT_PHP_VERSION
    if php_ver:
        _progress(f"Pulling PHP {php_ver} runtime image...")
        ok, msg = _pull_php_image(php_ver)
        results.append(f"PHP {php_ver}: {'OK' if ok else 'FAIL'} {msg}")
        if not ok:
            exit_code = 1
        else:
            pulled_php_versions.add(php_ver)

    if install_all or getattr(args, "mysql", False) or getattr(args, "mariadb", False):
        image = MARIADB_IMAGE
        _progress(f"Pulling {image} image...")
        proc = subprocess.run(["docker", "pull", image], check=False, capture_output=True, text=True)
        if proc.returncode == 0:
            results.append(f"MariaDB: OK pulled {image}")
        else:
            err = proc.stderr.strip() or proc.stdout.strip() or "pull failed"
            results.append(f"MariaDB: FAIL {err}")
            exit_code = proc.returncode or 1

    if install_all or getattr(args, "redis", False):
        image = REDIS_IMAGE
        _progress(f"Pulling {image} image...")
        proc = subprocess.run(["docker", "pull", image], check=False, capture_output=True, text=True)
        if proc.returncode == 0:
            results.append(f"Redis: OK pulled {image}")
        else:
            err = proc.stderr.strip() or proc.stdout.strip() or "pull failed"
            results.append(f"Redis: FAIL {err}")
            exit_code = proc.returncode or 1

    if getattr(args, "wpcli", False):
        if DEFAULT_PHP_VERSION in pulled_php_versions:
            results.append(f"wp-cli: OK using {php_image(DEFAULT_PHP_VERSION)} (bundled)")
        else:
            _progress(f"Pulling PHP {DEFAULT_PHP_VERSION} runtime image for WP-CLI...")
            ok, msg = _pull_php_image(DEFAULT_PHP_VERSION)
            results.append(f"wp-cli: {'OK' if ok else 'FAIL'} {msg} (bundled)")
            if not ok:
                exit_code = 1

    host_flags = ["netdata", "fail2ban", "ufw", "ngxblocker", "nanorc", "dashboard", "extplorer"]
    for flag in host_flags:
        if getattr(args, flag, False):
            results.append(f"{flag}: WARN not applicable in Docker-first wpfy (use host-level tooling separately)")

    helper_images = {
        "phpmyadmin": "phpmyadmin:5-apache",
        "adminer": "adminer:5",
        "composer": "composer:2",
    }
    for flag, image in helper_images.items():
        if getattr(args, flag, False):
            _progress(f"Pulling helper image {image}...")
            ok, msg = _pull_image(image)
            results.append(f"{flag}: {'OK' if ok else 'FAIL'} {msg}")
            if not ok:
                exit_code = 1
    if getattr(args, "mysqltuner", False):
        results.append("mysqltuner: WARN skipped; no vetted pinned container image yet")

    if len(results) == 1:
        results.append("nothing selected")
        results.append("hint: use --nginx, --php, --mysql, --redis, --wpcli, or --all")

    return CommandResult("\n".join(results), exit_code=exit_code)


def handle_stack_status(args: argparse.Namespace) -> CommandResult:
    results: list[str] = [_section("stack status")]

    status = traefik.traefik_status()
    results.append(f"Traefik: {status.message}")

    proc = subprocess.run(
        ["docker", "version", "--format", "{{.Server.Version}}"],
        check=False, capture_output=True, text=True,
    )
    if proc.returncode == 0 and proc.stdout.strip():
        results.append(f"Docker: {proc.stdout.strip()}")
    else:
        results.append("Docker: unavailable (is Docker installed and running?)")

    proc = subprocess.run(
        ["docker", "images", "--format", "{{.Repository}}:{{.Tag}}", f"{PHP_IMAGE_REPOSITORY}*"],
        check=False, capture_output=True, text=True,
    )
    if proc.returncode == 0 and proc.stdout.strip():
        results.append("Pulled wpfy images:")
        for line in proc.stdout.strip().splitlines():
            results.append(f"  - {line}")
    else:
        results.append("Pulled wpfy images: none found")

    return CommandResult("\n".join(results))


def handle_stack_remove(args: argparse.Namespace) -> CommandResult:
    result = traefik.stop_traefik()
    if result.skipped:
        return CommandResult(_render_summary("stack remove", [f"Traefik: SKIP {result.message}"]))
    if result.exit_code != 0:
        return CommandResult(_render_summary("stack remove", [f"Traefik: FAIL {result.message}"]), exit_code=result.exit_code)
    return CommandResult(_render_summary("stack remove", [f"Traefik: OK {result.message}"]))


def handle_stack_upgrade(args: argparse.Namespace) -> CommandResult:
    compose_file = traefik.traefik_compose_path()
    if not compose_file.exists():
        return CommandResult(
            _render_summary("stack upgrade", ["Traefik: FAIL not installed; run 'wpfy stack install --nginx' first"]),
            exit_code=2,
        )

    proc = subprocess.run(
        ["docker", "compose", "-f", str(compose_file), "pull"],
        cwd=traefik.traefik_dir(),
        check=False, capture_output=True, text=True,
    )
    if proc.returncode != 0:
        err = proc.stderr.strip() or proc.stdout.strip() or "pull failed"
        return CommandResult(_render_summary("stack upgrade", [f"Traefik: FAIL pull failed: {err}"]), exit_code=proc.returncode)

    proc2 = subprocess.run(
        ["docker", "compose", "-f", str(compose_file), "up", "-d"],
        cwd=traefik.traefik_dir(),
        check=False, capture_output=True, text=True,
    )
    if proc2.returncode != 0:
        err = proc2.stderr.strip() or proc2.stdout.strip() or "restart failed"
        return CommandResult(_render_summary("stack upgrade", [f"Traefik: FAIL restart failed: {err}"]), exit_code=proc2.returncode)

    lines = [_section("stack upgrade"), "Traefik: OK pulled latest images and restarted", "pull: complete"]
    return CommandResult("\n".join(lines))


def handle_stack_purge(args: argparse.Namespace) -> CommandResult:
    stop_result = traefik.stop_traefik()
    purge_msgs = [_section("stack purge"), _step_line("Traefik", stop_result)]

    compose_file = traefik.traefik_compose_path()
    if compose_file.exists():
        subprocess.run(
            ["docker", "compose", "-f", str(compose_file), "down", "--volumes", "--remove-orphans"],
            cwd=traefik.traefik_dir(),
            check=False, capture_output=True, text=True,
        )
        purge_msgs.append("compose project removed")

    purge_msgs.append(
        f"pulled images: docker rmi {php_image(DEFAULT_PHP_VERSION)} "
        f"{MARIADB_IMAGE} {REDIS_IMAGE} {traefik.TRAEFIK_IMAGE}"
    )
    return CommandResult("\n".join(purge_msgs))


def handle_stack_migrate(args: argparse.Namespace) -> CommandResult:
    return CommandResult(_render_summary("stack migrate", ["not implemented for Docker-first wpfy in v1"]))


def handle_site_create(args: argparse.Namespace) -> CommandResult:
    flavor_flags = [flag for flag in ("html", "mysql", "wp", "wpfc", "wpredis", "wpsc", "wprocket", "wpce", "wpsubdir", "wpsubdomain") if getattr(args, flag)]
    flavor = flavor_flags[0] if flavor_flags else "site"
    request = site_lifecycle.CreateSiteRequest(
        domain=args.domain,
        flavor=flavor,
        php_version=getattr(args, "php", DEFAULT_PHP_VERSION),
        letsencrypt=getattr(args, "letsencrypt", None),
        dns_provider=getattr(args, "dns", None),
        proxied_override=getattr(args, "proxied", None),
    )

    progress_messages = {
        "preflight": "Checking DNS/IP preflight for Let's Encrypt...",
        "scaffold": "Writing site scaffold...",
        "bootstrap": "Bootstrapping site files...",
        "runtime": "Starting site runtime...",
        "wordpress-state": "Checking WordPress install state...",
        "wordpress-provision": "Provisioning WordPress core and admin user. This can take a few seconds...",
    }
    try:
        result = site_lifecycle.create_site(
            request,
            credentials=lambda: _resolve_wp_admin_credentials(args, args.domain),
            progress=lambda step: _progress(progress_messages[step]),
        )
    except site_lifecycle.SiteLifecycleError as exc:
        if exc.preflight:
            return CommandResult(
                _render_summary(
                    "ssl preflight",
                    [
                        f"domain: {args.domain}",
                        "status: failed",
                        f"details: {exc}",
                        "next: no certificate was requested and no site files were changed",
                    ],
                ),
                exit_code=exc.exit_code,
            )
        return CommandResult(str(exc), exit_code=exc.exit_code)

    return CommandResult(
        _format_site_create_result(
            args.domain,
            flavor,
            _site_count_summary(list(result.touched)),
            result.bootstrap,
            result.runtime,
            wordpress_message=result.wordpress_message,
            wordpress_admin_user=result.wordpress_admin_user,
            generated_password=result.generated_password,
            preflight_message=result.preflight_message,
            created=result.created,
        ),
        exit_code=result.exit_code,
    )


def handle_site_update(args: argparse.Namespace) -> CommandResult:
    domain = args.domain
    request = site_lifecycle.UpdateSiteRequest(
        domain=domain,
        php_version=args.php,
        wpfc=args.wpfc,
        wpredis=args.wpredis,
        wpsubdir=args.wpsubdir,
        wpsubdomain=args.wpsubdomain,
        letsencrypt=args.letsencrypt,
        dns_provider=getattr(args, "dns", None),
        proxied_override=getattr(args, "proxied", None),
        password=args.password,
    )
    return _site_update_command_result(domain, request)


def handle_site_ssl(args: argparse.Namespace) -> CommandResult:
    domain = args.domain
    preflight_only = getattr(args, "preflight_only", False)
    renew = getattr(args, "renew", False)
    status_flag = getattr(args, "status", False)
    letsencrypt = getattr(args, "letsencrypt", None)

    if preflight_only:
        result = preflight_ssl(domain)
        lines = [
            _section("ssl preflight"),
            f"domain: {domain}",
            f"status: {'passed' if result.passed else 'failed'}",
            f"mode: {result.mode or 'direct'}",
            f"details: {result.message}",
        ]
        return CommandResult("\n".join(lines), exit_code=0 if result.passed else 2)

    if renew:
        result = force_renew_cert(domain)
        return CommandResult(_render_summary("ssl renew", [_step_line("traefik", result)]), exit_code=result.exit_code)

    if status_flag or not letsencrypt:
        cert_info = get_cert_info(domain)
        status = cert_info.get("status", "unknown")
        if status == "unavailable":
            return CommandResult(
                _render_summary(
                    "ssl status",
                    [f"domain: {domain}", "status: unavailable (Traefik/ACME not yet initialized)"],
                ),
                exit_code=2,
            )
        if status == "empty":
            return CommandResult(_render_summary("ssl status", [f"domain: {domain}", "status: no certificates issued yet"]))
        if status == "not_found":
            return CommandResult(_render_summary("ssl status", [f"domain: {domain}", "status: no certificate found"]), exit_code=2)

        issuer = cert_info.get("issuer", "unknown")
        not_before = cert_info.get("not_before", "unknown")
        not_after = cert_info.get("not_after", "unknown")
        sans = cert_info.get("sans", [])
        expiry_days = cert_expiry_days(domain)
        lines = [
            _section("ssl status"),
            f"domain: {domain}",
            f"status: {status}",
            f"issuer: {issuer}",
            f"valid from: {not_before}",
            f"valid until: {not_after}",
        ]
        if expiry_days is not None:
            lines.append(f"expires in: {expiry_days} days")
        if sans:
            lines.append(f"SANs: {', '.join(sans)}")
        return CommandResult("\n".join(lines))

    try:
        result = site_lifecycle.enable_ssl(
            domain,
            letsencrypt=letsencrypt,
            dns_provider=getattr(args, "dns", None),
            proxied_override=getattr(args, "proxied", None),
        )
    except site_lifecycle.SiteLifecycleError as exc:
        if exc.preflight:
            return CommandResult(
                _render_summary(
                    "ssl preflight",
                    [
                        f"domain: {domain}",
                        "status: failed",
                        f"details: {exc}",
                        "next: no certificate was requested and no changes were made",
                    ],
                ),
                exit_code=exc.exit_code,
            )
        return CommandResult(str(exc), exit_code=exc.exit_code)

    lines = [
        _section("ssl enabled"),
        f"domain: {domain}",
        f"preflight: {result.preflight_message}",
        f"scaffold: {_site_count_summary(list(result.touched))}",
        _step_line("runtime", result.runtime),
    ]
    if result.wordpress_message:
        lines.append(f"wordpress: {result.wordpress_message}")
    lines.append("next: make an HTTPS request to the site to trigger certificate issuance")
    return CommandResult("\n".join(lines), exit_code=result.exit_code)


def handle_site_backup(args: argparse.Namespace) -> CommandResult:
    keep_local = getattr(args, "keep_local", None)
    if keep_local is not None and keep_local < 0:
        return CommandResult("keep-local must be 0 or greater", exit_code=2)
    backup_kwargs = {
        "destination_dir": getattr(args, "destination_dir", None),
        "upload_s3": getattr(args, "s3", False),
    }
    if getattr(args, "profile", None):
        backup_kwargs["s3_profile"] = getattr(args, "profile", None)
    if keep_local is not None:
        backup_kwargs["keep_local"] = keep_local
    if getattr(args, "list", False):
        if args.domain == "all":
            return CommandResult("backup all does not support --list", exit_code=2)
        try:
            archives = list_backup_archives(args.domain)
        except ValueError as exc:
            return CommandResult(str(exc), exit_code=2)
        lines = [str(path) for path in archives] or ["no backup archives found"]
        return CommandResult(_render_summary("backup archives", lines))

    if args.domain == "all":
        sites = sorted(list_sites(), key=lambda site: site.get("domain", ""))
        if not sites:
            return CommandResult("no managed sites found")
        lines = []
        exit_code = 0
        for site in sites:
            domain = site.get("domain", "")
            result = backup_site(
                domain,
                **backup_kwargs,
            )
            if result.exit_code != 0:
                exit_code = 1
            lines.append(_step_line(domain, result))
        return CommandResult(_render_summary("site backup all", lines), exit_code=exit_code)

    result = backup_site(
        args.domain,
        **backup_kwargs,
    )
    return CommandResult(_render_summary("site backup", [_step_line("backup", result)]), exit_code=result.exit_code)


def _s3_config_summary(config: S3Config) -> list[str]:
    return [
        f"endpoint: {config.endpoint}",
        f"bucket: {config.bucket}",
        f"region: {config.region}",
        f"prefix: {config.prefix or '(none)'}",
        "access key: configured",
        "secret key: configured",
    ]


def _load_backup_storage(profile: str | None = None) -> tuple[S3Config | None, CommandResult | None]:
    try:
        return load_s3_config(profile), None
    except RuntimeError as exc:
        return None, CommandResult(str(exc), exit_code=2)


def _secret_from_args(args: argparse.Namespace) -> tuple[str | None, CommandResult | None]:
    if getattr(args, "secret_key_stdin", False):
        secret_key = sys.stdin.readline().rstrip("\r\n")
        if not secret_key:
            return None, CommandResult("secret key required on stdin", exit_code=2)
        return secret_key, None
    if not sys.stdin.isatty():
        return None, CommandResult("secret key prompt requires a TTY; use --secret-key-stdin for scripts", exit_code=2)
    secret_key = getpass.getpass("S3 secret key: ")
    if not secret_key:
        return None, CommandResult("secret key cannot be empty", exit_code=2)
    return secret_key, None


def handle_backup_storage(args: argparse.Namespace) -> CommandResult:
    profile = getattr(args, "profile", None)
    if args.storage_command == "set":
        secret_key, secret_error = _secret_from_args(args)
        if secret_error:
            return secret_error
        if secret_key is None:
            return CommandResult("secret key required", exit_code=2)
        config = S3Config(
            endpoint=args.endpoint,
            bucket=args.bucket,
            region=args.region,
            prefix=args.prefix,
            access_key=args.access_key,
            secret_key=secret_key,
        )
        path = write_s3_config(config, profile)
        stored = load_s3_config(profile)
        return CommandResult(
            _render_summary("backup storage", [*_s3_config_summary(stored), f"config: {path}"])
        )

    if args.storage_command == "status":
        config, error = _load_backup_storage(profile)
        if error:
            return error
        if config is None:
            return CommandResult("backup storage is not configured", exit_code=2)
        return CommandResult(_render_summary("backup storage", _s3_config_summary(config)))

    if args.storage_command == "test":
        config, error = _load_backup_storage(profile)
        if error:
            return error
        if config is None:
            return CommandResult("backup storage is not configured", exit_code=2)
        key = s3_object_key(config.prefix, "", ".wpfy-test")
        try:
            uploaded_to = S3Uploader().upload_bytes(config, key, b"wpfy backup storage test\n")
        except (OSError, RuntimeError) as exc:
            return CommandResult(f"upload: FAIL {redact_s3_secrets(str(exc), config)}", exit_code=4)
        return CommandResult(_render_summary("backup storage test", [f"upload: OK {uploaded_to}"]))

    if args.storage_command == "clear":
        if not args.force:
            return CommandResult("backup storage clear aborted: --force required", exit_code=2)
        clear_s3_config(profile)
        return CommandResult(_render_summary("backup storage", [f"removed: {s3_config_path(profile)}"]))

    return CommandResult("backup storage command required", exit_code=2)


def handle_backup_prune(args: argparse.Namespace) -> CommandResult:
    if args.domain == "all":
        sites = sorted(list_sites(), key=lambda site: site.get("domain", ""))
        if not sites:
            return CommandResult("no managed sites found")
        lines = []
        exit_code = 0
        for site in sites:
            result = prune_backup_archives(site.get("domain", ""), args.keep, dry_run=args.dry_run)
            if result.exit_code != 0:
                exit_code = 1
            lines.append(_step_line(site.get("domain", ""), result))
        return CommandResult(_render_summary("backup prune", lines), exit_code=exit_code)
    result = prune_backup_archives(args.domain, args.keep, dry_run=args.dry_run)
    return CommandResult(_render_summary("backup prune", [_step_line("prune", result)]), exit_code=result.exit_code)


def handle_backup_edge(args: argparse.Namespace) -> CommandResult:
    result = edge_backup.backup_edge(
        destination_dir=getattr(args, "destination_dir", None),
        upload_s3=getattr(args, "s3", False),
        s3_profile=getattr(args, "profile", None),
    )
    return CommandResult(_render_summary("backup edge", [_step_line("edge", result)]), exit_code=result.exit_code)


def _remote_prefix(config: S3Config, domain: str) -> str:
    return f"{s3_object_key(config.prefix, domain, '')}/"


def _remote_key_allowed(config: S3Config, domain: str, key: str) -> bool:
    prefix = _remote_prefix(config, domain)
    return key.startswith(prefix) and key.endswith(".tar.gz") and "/" not in key.removeprefix(prefix).strip("/")


def _remote_archive_keys(config: S3Config, domain: str, uploader: S3Uploader) -> list[str]:
    prefix = _remote_prefix(config, domain)
    keys = uploader.list_keys(config, prefix)
    return sorted([key for key in keys if _remote_key_allowed(config, domain, key)], reverse=True)


def _load_remote(profile: str | None) -> tuple[S3Config | None, S3Uploader | None, CommandResult | None]:
    config, error = _load_backup_storage(profile)
    if error:
        return None, None, error
    if config is None:
        return None, None, CommandResult("backup storage is not configured", exit_code=2)
    return config, S3Uploader(), None


def handle_backup_remote(args: argparse.Namespace) -> CommandResult:
    config, uploader, error = _load_remote(getattr(args, "profile", None))
    if error:
        return error
    if config is None or uploader is None:
        return CommandResult("backup storage is not configured", exit_code=2)
    try:
        validate_domain(args.domain)
    except ValueError as exc:
        return CommandResult(redact_s3_secrets(str(exc), config), exit_code=2)

    if args.remote_command == "delete":
        if not args.force:
            return CommandResult("backup remote delete aborted: --force required", exit_code=2)
        if not _remote_key_allowed(config, args.domain, args.key):
            return CommandResult("remote key outside managed backup prefix", exit_code=2)
        try:
            deleted = uploader.delete_key(config, args.key)
        except (OSError, RuntimeError) as exc:
            return CommandResult(f"delete: FAIL {redact_s3_secrets(str(exc), config)}", exit_code=4)
        return CommandResult(_render_summary("backup remote delete", [f"deleted: {deleted}"]))

    try:
        keys = _remote_archive_keys(config, args.domain, uploader)
    except (OSError, RuntimeError) as exc:
        return CommandResult(redact_s3_secrets(str(exc), config), exit_code=2)

    if args.remote_command == "list":
        lines = [f"s3://{config.bucket}/{key}" for key in keys] or ["no remote backup archives found"]
        return CommandResult(_render_summary("backup remote list", lines))

    if args.remote_command == "restore":
        key = keys[0] if getattr(args, "latest", False) and keys else getattr(args, "key", "")
        if not key:
            return CommandResult("no remote backup archives found", exit_code=2)
        if not _remote_key_allowed(config, args.domain, key):
            return CommandResult("remote key outside managed backup prefix", exit_code=2)
        try:
            payload = uploader.download_bytes(config, key)
        except (OSError, RuntimeError) as exc:
            return CommandResult(f"download: FAIL {redact_s3_secrets(str(exc), config)}", exit_code=4)
        with tempfile.NamedTemporaryFile(prefix="wpfy-remote-restore-", suffix=".tar.gz", delete=False) as archive:
            archive.write(payload)
            archive_path = archive.name
        try:
            result = restore_site(args.domain, archive_path)
        finally:
            Path(archive_path).unlink(missing_ok=True)
        return CommandResult(_render_summary("backup remote restore", [_step_line("restore", result)]), result.exit_code)

    if args.remote_command == "prune":
        if args.keep < 0:
            return CommandResult("keep must be 0 or greater", exit_code=2)
        victims = keys[args.keep:]
        if not victims:
            return CommandResult(_render_summary("backup remote prune", ["no remote backups pruned"]))
        if args.dry_run:
            return CommandResult(_render_summary("backup remote prune", [f"would delete: s3://{config.bucket}/{key}" for key in victims]))
        if not args.force:
            return CommandResult("backup remote prune aborted: --force required", exit_code=2)
        lines = []
        exit_code = 0
        for key in victims:
            try:
                lines.append(f"deleted: {uploader.delete_key(config, key)}")
            except (OSError, RuntimeError) as exc:
                exit_code = 4
                lines.append(f"FAIL {redact_s3_secrets(str(exc), config)}")
        return CommandResult(_render_summary("backup remote prune", lines), exit_code=exit_code)

    return CommandResult("backup remote command required", exit_code=2)


def handle_backup_schedule(args: argparse.Namespace) -> CommandResult:
    if args.schedule_command == "status":
        result = backup_schedule.schedule_status()
        return CommandResult(_render_summary("backup schedule", [_step_line("schedule", result)]), result.exit_code)

    if args.schedule_command == "disable":
        result = backup_schedule.disable_schedule()
        return CommandResult(_render_summary("backup schedule", [_step_line("schedule", result)]), result.exit_code)

    if args.schedule_command in {"daily", "weekly"}:
        if not backup_schedule.validate_time(args.time):
            return CommandResult("invalid time: use HH:MM in 24-hour format", exit_code=2)
        weekday = getattr(args, "weekday", None)
        if args.schedule_command == "weekly":
            weekday = str(weekday).lower()
            if not backup_schedule.validate_weekday(weekday):
                return CommandResult("invalid weekday: use mon, tue, wed, thu, fri, sat, or sun", exit_code=2)
        if getattr(args, "s3", False):
            _, error = _load_backup_storage()
            if error:
                return error
        schedule = backup_schedule.BackupSchedule(
            cadence=args.schedule_command,
            time=args.time,
            destination_dir=getattr(args, "destination_dir", None),
            upload_s3=getattr(args, "s3", False),
            weekday=weekday,
        )
        result = backup_schedule.install_schedule(schedule)
        return CommandResult(_render_summary("backup schedule", [_step_line("schedule", result)]), result.exit_code)

    return CommandResult("backup schedule command required", exit_code=2)


def handle_cron(args: argparse.Namespace) -> CommandResult:
    if args.cron_command == "install":
        result = cron.install_timers()
        return CommandResult(_render_summary("cron", [_step_line("timers", result)]), result.exit_code)
    if args.cron_command == "status":
        result = cron.timers_status()
        return CommandResult(_render_summary("cron", [_step_line("timers", result)]), result.exit_code)
    if args.cron_command == "disable":
        result = cron.disable_timers()
        return CommandResult(_render_summary("cron", [_step_line("timers", result)]), result.exit_code)
    if args.cron_command in cron.INTERVALS:
        result = cron.run_interval(args.cron_command)
        return CommandResult(_render_summary("cron", list(result.lines)), result.exit_code)
    return CommandResult("cron command required", exit_code=2)


def _smtp_password_from_args(args: argparse.Namespace) -> tuple[str | None, CommandResult | None]:
    if getattr(args, "password_stdin", False):
        password = sys.stdin.readline().rstrip("\r\n")
        if not password:
            return None, CommandResult("SMTP password required on stdin", exit_code=2)
        return password, None
    if not sys.stdin.isatty():
        return None, CommandResult("SMTP password prompt requires a TTY; use --password-stdin for scripts", exit_code=2)
    password = getpass.getpass("SMTP password: ")
    if not password:
        return None, CommandResult("SMTP password cannot be empty", exit_code=2)
    return password, None


def _load_smtp() -> tuple[SMTPConfig | None, CommandResult | None]:
    try:
        return smtp.load_smtp_config(), None
    except RuntimeError as exc:
        return None, CommandResult(str(exc), exit_code=2)


def handle_smtp(args: argparse.Namespace) -> CommandResult:
    if args.smtp_command == "set":
        password, password_error = _smtp_password_from_args(args)
        if password_error:
            return password_error
        if password is None:
            return CommandResult("SMTP password required", exit_code=2)
        config = SMTPConfig(
            host=args.host,
            port=args.port,
            sender=args.sender,
            username=args.username,
            password=password,
            tls=args.tls,
        )
        path = smtp.write_smtp_config(config)
        stored = smtp.load_smtp_config()
        return CommandResult(_render_summary("smtp", [*smtp.smtp_status_lines(stored), f"config: {path}"]))

    if args.smtp_command == "status":
        config, error = _load_smtp()
        if error:
            return error
        if config is None:
            return CommandResult("smtp is not configured", exit_code=2)
        return CommandResult(_render_summary("smtp", smtp.smtp_status_lines(config)))

    if args.smtp_command == "test":
        config, error = _load_smtp()
        if error:
            return error
        if config is None:
            return CommandResult("smtp is not configured", exit_code=2)
        if not args.dry_run and not args.to:
            return CommandResult("smtp test requires --dry-run or --to", exit_code=2)
        recipient = args.to or config.sender
        try:
            message = smtp.send_test_message(config, recipient, dry_run=args.dry_run)
        except (OSError, RuntimeError, smtplib.SMTPException) as exc:
            return CommandResult(f"smtp test: FAIL {smtp.redact_smtp_secret(str(exc), config)}", exit_code=4)
        return CommandResult(_render_summary("smtp test", [message]))

    if args.smtp_command == "clear":
        if not args.force:
            return CommandResult("smtp clear aborted: --force required", exit_code=2)
        smtp.clear_smtp_config()
        return CommandResult(_render_summary("smtp", [f"removed: {smtp.smtp_config_path()}"]))

    return CommandResult("smtp command required", exit_code=2)


def handle_dns(args: argparse.Namespace) -> CommandResult:
    if args.dns_provider != "cloudflare":
        return CommandResult("dns provider required", exit_code=2)
    if args.dns_command == "set":
        if not getattr(args, "token_stdin", False):
            return CommandResult("Cloudflare token required on stdin; use --token-stdin", exit_code=2)
        token = sys.stdin.readline().rstrip("\r\n")
        if not token:
            return CommandResult("Cloudflare token cannot be empty", exit_code=2)
        path = dns.write_cloudflare_config(dns.CloudflareConfig(token=token))
        return CommandResult(_render_summary("dns cloudflare", ["token: configured", f"config: {path}"]))
    if args.dns_command == "status":
        try:
            dns.load_cloudflare_config()
        except dns.DNSConfigError as exc:
            return CommandResult(str(exc), exit_code=2)
        return CommandResult(_render_summary("dns cloudflare", ["token: configured"]))
    if args.dns_command == "test":
        try:
            config = dns.load_cloudflare_config()
            message = dns.test_cloudflare_config(config)
        except (dns.DNSConfigError, OSError) as exc:
            text = str(exc)
            if "config" in locals():
                text = dns.redact_cloudflare_secret(text, config)
            return CommandResult(f"Cloudflare DNS test failed: {text}", exit_code=4)
        return CommandResult(_render_summary("dns cloudflare test", [f"test: OK {message}"]))
    if args.dns_command == "clear":
        if not args.force:
            return CommandResult("dns cloudflare clear aborted: --force required", exit_code=2)
        dns.clear_cloudflare_config()
        return CommandResult(_render_summary("dns cloudflare", [f"removed: {dns.cloudflare_config_path()}"]))
    return CommandResult("dns cloudflare command required", exit_code=2)


def handle_site_restore(args: argparse.Namespace) -> CommandResult:
    if getattr(args, "list", False):
        try:
            archives = list_backup_archives(args.domain)
        except ValueError as exc:
            return CommandResult(str(exc), exit_code=2)
        lines = [str(path) for path in archives] or ["no backup archives found"]
        return CommandResult(_render_summary("restore archives", lines))
    if getattr(args, "latest", False):
        latest = latest_backup_archive(args.domain)
        if latest.exit_code != 0:
            return CommandResult(_render_summary("site restore", [_step_line("latest", latest)]), exit_code=latest.exit_code)
        result = restore_site(args.domain, latest.message)
        return CommandResult(_render_summary("site restore", [_step_line("restore", result)]), exit_code=result.exit_code)
    if not args.backup:
        return CommandResult("restore backup archive required unless --list is used", exit_code=2)
    result = restore_site(args.domain, args.backup)
    return CommandResult(_render_summary("site restore", [_step_line("restore", result)]), exit_code=result.exit_code)


def handle_restore_edge(args: argparse.Namespace) -> CommandResult:
    result = edge_backup.restore_edge(args.archive, force=getattr(args, "force", False))
    return CommandResult(_render_summary("restore edge", [_step_line("edge", result)]), exit_code=result.exit_code)


def handle_site_wp(args: argparse.Namespace) -> CommandResult:
    domain = args.domain
    if not site_exists(domain):
        return CommandResult(f"site not found: {domain}", exit_code=2)

    wp_args = list(args.wp_args or [])
    # The wpcli container runs as the site's non-root uid; --allow-root is a
    # harmless no-op there (wp-cli only treats uid 0 as root) and is kept for
    # parity with the bootstrap path.
    if "--allow-root" not in wp_args:
        wp_args.append("--allow-root")
    compose_file = str(compose_path(domain))
    site_directory = str(site_dir(domain))

    cmd = ["docker", "compose", "-f", compose_file, "run", "--rm", "wpcli", *wp_args]

    proc = subprocess.run(
        cmd,
        cwd=site_directory,
        check=False,
    )

    return CommandResult("", exit_code=proc.returncode)


def _label(ok: bool | None) -> str:
    if ok is None:
        return "WARN"
    return "PASS" if ok else "FAIL"


def handle_debug(args: argparse.Namespace) -> CommandResult:
    domain: str | None = getattr(args, "domain", None)
    lines: list[str] = []
    has_fail = False
    has_warn = False

    lines.append("=== wpfy diagnostic report ===")
    system_checks = operational_inspection.system_diagnostics()
    for check in system_checks:
        lines.append(f"[{_label(check.ok)}] {check.name}: {check.message}")
        if check.ok is False:
            has_fail = True
    if system_checks and system_checks[0].ok is False:
        lines.append("FATAL: Docker not available — aborting")
        return CommandResult("\n".join(lines), exit_code=1)

    if domain:
        lines.append(f"\n=== site: {domain} ===")
        site_checks = operational_inspection.site_diagnostics(domain)
        for check in site_checks:
            lines.append(f"[{_label(check.ok)}] {check.name}: {check.message}")
            if check.ok is False:
                has_fail = True
            elif check.ok is None:
                has_warn = True
    else:
        sites = list_sites()
        if not sites:
            lines.append("\n(no sites found)")
        for site in sites:
            d = site["domain"]
            lines.append(f"\n=== site: {d} ===")
            site_checks = operational_inspection.site_diagnostics(d)
            for check in site_checks:
                lines.append(f"[{_label(check.ok)}] {check.name}: {check.message}")
                if check.ok is False:
                    has_fail = True
                elif check.ok is None:
                    has_warn = True

    lines.append(f"\n=== summary ===")
    if has_fail:
        lines.append("result: FAIL")
    elif has_warn:
        lines.append("result: WARN")
    else:
        lines.append("result: PASS")

    return CommandResult("\n".join(lines), exit_code=1 if has_fail else 0)


def add_debug_parser(subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    parser = _add_parser(
        subparsers,
        "debug",
        help="Run diagnostics across Docker, Traefik, and managed sites.",
    )
    parser.add_argument("domain", nargs="?")
    parser.set_defaults(handler=handle_debug)


def _normalize_exec_argv(argv: list[str]) -> list[str]:
    if not argv or argv[0] != "exec" or "--" not in argv:
        return argv
    marker = argv.index("--")
    before = argv[:marker]
    after = argv[marker + 1 :]
    if len(before) == 2:
        return [*before, "app", *after]
    if len(before) == 3:
        return [*before, *after]
    return argv


def _normalize_backup_argv(argv: list[str]) -> list[str]:
    if len(argv) >= 2 and argv[0] == "backup" and argv[1] in {"storage", "schedule", "prune", "remote", "edge"}:
        return [f"backup-{argv[1]}", *argv[2:]]
    if len(argv) >= 2 and argv[0] == "restore" and argv[1] == "edge":
        return ["restore-edge", *argv[2:]]
    return argv


def run(argv: Iterable[str] | None = None) -> int:
    parser = build_parser()
    raw_argv = list(argv) if argv is not None else sys.argv[1:]
    args = parser.parse_args(_normalize_exec_argv(_normalize_backup_argv(raw_argv)))

    if not hasattr(args, "handler"):
        parser.print_help()
        return 0

    result = args.handler(args)
    print(result.message)
    return result.exit_code


def main(argv: Iterable[str] | None = None) -> int:
    return run(argv)
