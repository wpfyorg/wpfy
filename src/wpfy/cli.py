from __future__ import annotations

import argparse
from datetime import datetime
import getpass
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
from . import cache_operations
from . import site_cache
from . import site_cron
from . import site_security
from . import cron
from . import dns
from . import edge_backup
from . import events
from . import files
from . import metrics
from . import panel
from . import panel_auth
from . import panel_exposure
from . import registry
from . import smtp
from . import sftp
from . import site_database
from . import site_configuration
from . import site_lifecycle
from . import stack
from . import telemetry
from . import operational_inspection
from .php_runtime import DEFAULT_PHP_VERSION, SUPPORTED_PHP_VERSIONS
from .certificate_lifecycle import cert_expiry_days, force_renew_cert, get_cert_info, preflight_ssl
from .site_definition import DNS_PROVIDERS, LETSENCRYPT_MODES, PAGE_CACHE_OPTIONS, SiteDefinition
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
    WORDPRESS_FLAVORS,
    backup_site,
    ensure_site_scaffold,
    generated_secret,
    get_nginx_custom,
    latest_backup_archive,
    list_backup_archives,
    list_sites,
    remove_site_scaffold,
    prune_backup_archives,
    restore_site,
    site_info,
    set_nginx_custom,
    validate_nginx_custom,
    validate_php_custom,
)
from .site_paths import (
    app_dir,
    compose_path,
    domain_to_project,
    env_path,
    nginx_dir,
    read_env,
    site_exists,
    validate_domain,
)
from .site_runtime import (
    RuntimeResult,
    app_health_ok,
    compose_command,
    reset_site_logs,
    run_wp_cli,
    runtime_skip_requested,
    site_logs,
    site_health,
    start_site_runtime,
    stop_site_runtime,
)


class WpfyHelpFormatter(argparse.ArgumentDefaultsHelpFormatter, argparse.RawDescriptionHelpFormatter):
    pass


@dataclass(frozen=True, slots=True)
class CommandResult:
    message: str
    exit_code: int = 0
    raw_output: bool = False


DISK_THRESHOLDS: Final = (80.0, 90.0)
LOAD_THRESHOLDS: Final = (1.5, 3.0)


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


def _site_ssl_observation(site: dict) -> tuple[str, dict]:
    domain = str(site.get("domain", ""))
    configured = site.get("ssl_enabled", site.get("ssl", "disabled"))
    if _enabled_text(configured) != "enabled":
        return "disabled", {"status": "disabled"}
    try:
        certificate = get_cert_info(domain)
    except (OSError, ValueError):
        certificate = {"status": "unavailable"}
    if certificate.get("status") == "issued":
        return "enabled", certificate
    return "requested", certificate


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


def _site_create_next_steps(
    domain: str,
    flavor: str,
    page_cache: str = "none",
    object_cache: str = "none",
) -> list[str]:
    steps: list[str] = []
    if flavor in WORDPRESS_FLAVORS:
        steps.append(f"sign in at https://{domain}/wp-admin")
    if page_cache in {"wp-rocket", "flying-press"}:
        plugin_dir = app_dir(domain) / "wp-content" / "plugins"
        steps.append(
            f"upload and extract the licensed {page_cache} zip under {plugin_dir}; "
            "wpfy server-side cache rules are already staged"
        )
    if object_cache == "redis":
        steps.append("Redis object cache is wired to this site's private redis service")
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
    page_cache: str = "none",
    object_cache: str = "none",
    cache_message: str | None = None,
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
    if cache_message:
        lines.append(f"cache: {cache_message}")
    if wordpress_message:
        lines.append(f"wordpress: {wordpress_message}")
    if wordpress_admin_user:
        lines.append(f"admin user: {wordpress_admin_user}")
    if generated_password:
        lines.append(f"generated password: {generated_password}")
    next_steps = _site_create_next_steps(domain, flavor, page_cache, object_cache)
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
    add_db_parser(subparsers)
    add_cache_parser(subparsers)
    add_run_parser(subparsers)
    add_backup_parser(subparsers)
    add_backup_prune_parser(subparsers)
    add_backup_remote_parser(subparsers)
    add_backup_edge_parser(subparsers)
    add_backup_storage_parser(subparsers)
    add_backup_schedule_parser(subparsers)
    add_cron_parser(subparsers)
    add_metrics_parser(subparsers)
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
    add_panel_parser(subparsers)
    add_telemetry_parser(subparsers)
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
    services = parser.add_mutually_exclusive_group()
    services.add_argument("--nginx", action="store_true")
    services.add_argument("--php", action="store_true")
    services.add_argument("--mysql", action="store_true")
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


def _render_service_info(info: operational_inspection.ServiceInfo) -> CommandResult:
    lines = [_section(info.heading)]
    for check in info.checks:
        lines.append(f"{check.name}:")
        lines.extend(f"  {line}" for line in check.message.splitlines())
    failed = any(check.ok is False for check in info.checks)
    return CommandResult("\n".join(lines), exit_code=1 if failed else 0)


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
        return _render_service_info(operational_inspection.nginx_service_info(domain))

    if want_php:
        if not site_exists(domain):
            return CommandResult(f"site not found: {domain}", exit_code=2)
        return _render_service_info(operational_inspection.php_service_info(domain))

    if want_mysql:
        if not site_exists(domain):
            return CommandResult(f"site not found: {domain}", exit_code=2)
        return _render_service_info(operational_inspection.mysql_service_info(domain))

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


def _cache_configuration_result(result: site_cache.CacheConfigurationResult, title: str) -> CommandResult:
    lines = [
        _section(title),
        f"domain: {result.definition.domain}",
        f"page cache: {result.definition.page_cache}",
        f"object cache: {result.definition.object_cache}",
        f"scaffold: {_site_count_summary(list(result.touched))}",
    ]
    for action in result.actions:
        lines.append(f"{action.status}: {action.message}")
    return CommandResult("\n".join(lines), exit_code=result.exit_code)


def handle_cache(args: argparse.Namespace) -> CommandResult:
    domain = args.domain
    try:
        if args.cache_command == "show":
            definition, error = _site_definition_from_env(domain)
            if error:
                return error
            if definition is None:
                return CommandResult("cache config could not be loaded", exit_code=2)
            return CommandResult(_render_summary(
                "site cache",
                [
                    f"domain: {domain}",
                    f"page cache: {definition.page_cache}",
                    f"object cache: {definition.object_cache}",
                    f"nginx rules: {nginx_dir(domain) / 'extra' / 'wpfy-cache.conf'}",
                ],
            ))
        if args.cache_command == "set":
            return _cache_configuration_result(
                site_cache.set_page_cache(domain, args.plugin),
                "page cache",
            )
        if args.cache_command == "object":
            return _cache_configuration_result(
                site_cache.set_object_cache(domain, args.backend),
                "object cache",
            )
        if args.cache_command == "purge":
            result = site_cache.purge_site_cache(domain)
            lines = [_section("cache purge"), f"domain: {domain}"]
            lines.extend(f"{outcome.cache}: {outcome.status} {outcome.message}" for outcome in result.outcomes)
            return CommandResult("\n".join(lines), exit_code=result.exit_code)
    except (FileNotFoundError, ValueError, OSError) as exc:
        return CommandResult(str(exc), exit_code=2)
    return CommandResult("cache command required", exit_code=2)


def add_cache_parser(subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    parser = _add_parser(
        subparsers,
        "cache",
        help="Configure and purge native WordPress cache integrations.",
    )
    parser.add_argument("domain")
    commands = parser.add_subparsers(dest="cache_command")

    _add_parser(commands, "show", help="Show page and object cache selection.").set_defaults(handler=handle_cache)

    set_parser = _add_parser(commands, "set", help="Set the WordPress page-cache integration.")
    set_parser.add_argument("plugin", choices=sorted(PAGE_CACHE_OPTIONS))
    set_parser.set_defaults(handler=handle_cache)

    object_parser = _add_parser(commands, "object", help="Set the WordPress object-cache backend.")
    object_parser.add_argument("backend", choices=("redis", "none"))
    object_parser.set_defaults(handler=handle_cache)

    _add_parser(commands, "purge", help="Purge plugin, Nginx, and Redis cache layers.").set_defaults(
        handler=handle_cache,
    )


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
    result = cache_operations.clear(cache_operations.CacheRequest(
        domain=getattr(args, "domain", None),
        redis=getattr(args, "redis", False),
        opcache=getattr(args, "opcache", False),
        clear_all=getattr(args, "all", False),
    ))
    messages: list[str] = []
    errors: list[str] = []
    for outcome in result.outcomes:
        if outcome.cache == "site":
            line = f"[{outcome.domain}] skipped: {outcome.message}"
        elif outcome.cache == "nginx":
            line = (
                f"[{outcome.domain}] nginx cache cleared"
                if outcome.status == "ok"
                else f"[{outcome.domain}] nginx cache: {outcome.message}"
            )
        elif outcome.cache == "redis":
            if outcome.status == "ok":
                line = f"[{outcome.domain}] redis cache flushed"
            elif outcome.status == "skipped":
                line = f"[{outcome.domain}] redis: {outcome.message} (skipped)"
            else:
                line = f"[{outcome.domain}] redis: {outcome.message}"
        else:
            line = (
                f"[{outcome.domain}] opcache reset"
                if outcome.status == "ok"
                else f"[{outcome.domain}] opcache: {outcome.message}"
            )
        (errors if outcome.status == "error" else messages).append(line)

    lines = [_section("cache clear")]
    if result.no_sites_found:
        lines.append("no managed sites found")
    elif messages:
        lines.extend(messages)
    else:
        lines.append("nothing cleared")
    if errors:
        lines.append("errors:")
        lines.extend(f"  {error}" for error in errors)
    return CommandResult("\n".join(lines), exit_code=result.exit_code)


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
    actions = parser.add_mutually_exclusive_group()
    actions.add_argument("--enable", action="store_true", help="enable maintenance mode (stop app container)")
    actions.add_argument("--disable", action="store_true", help="disable maintenance mode (start app container)")
    actions.add_argument("--status", action="store_true", help="show maintenance status")
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
        try:
            proc = compose_command(domain, "stop", "app")
        except OSError as exc:
            return CommandResult(f"maintenance enable failed: {exc}", exit_code=1)
        if proc.returncode != 0:
            error = (
                proc.stderr.strip() or proc.stdout.strip() or "docker compose stop failed"
            ).splitlines()[-1]
            return CommandResult(f"maintenance enable failed: {error}", exit_code=proc.returncode or 1)
        try:
            registry.update_site(domain, {"maintenance": "enabled"})
        except OSError as exc:
            return CommandResult(
                f"maintenance runtime enabled but registry update failed: {exc}", exit_code=1
            )
        return CommandResult(_render_summary(
            "maintenance mode",
            [f"domain: {domain}", "action: enabled (app container stopped)"],
        ))

    if disable:
        try:
            proc = compose_command(domain, "start", "app")
        except OSError as exc:
            return CommandResult(f"maintenance disable failed: {exc}", exit_code=1)
        if proc.returncode != 0:
            error = (
                proc.stderr.strip() or proc.stdout.strip() or "docker compose start failed"
            ).splitlines()[-1]
            return CommandResult(f"maintenance disable failed: {error}", exit_code=proc.returncode or 1)
        try:
            registry.update_site(domain, {"maintenance": "disabled"})
        except OSError as exc:
            return CommandResult(
                f"maintenance runtime disabled but registry update failed: {exc}", exit_code=1
            )
        return CommandResult(_render_summary(
            "maintenance mode",
            [f"domain: {domain}", "action: disabled (app container started)"],
        ))

    return CommandResult(_render_summary("maintenance mode", ["no action taken"]))


def add_update_parser(subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    parser = _add_parser(
        subparsers,
        "update",
        help="Check for and install new wpfy releases.",
    )
    actions = parser.add_mutually_exclusive_group()
    actions.add_argument("--check", action="store_true", help="check published version metadata (PyPI)")
    actions.add_argument("--force", action="store_true", help="force upgrade wpfy via pip")
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
        if not isinstance(latest, str) or not latest.strip():
            raise ValueError("PyPI version is missing or invalid")
    except (URLError, json.JSONDecodeError, KeyError, TypeError, ValueError, OSError) as e:
        if force:
            return CommandResult(_render_summary("wpfy update", [f"version: {current_version}", f"FAIL cannot fetch latest version from PyPI: {e}"]), exit_code=2)
        return CommandResult(_render_summary("wpfy update", [f"version: {current_version}", f"PyPI check unavailable: {e}"]))

    if check:
        if current_version == latest:
            return CommandResult(_render_summary("wpfy update", [f"installed: {current_version}", "status: up-to-date"]))
        return CommandResult(_render_summary(
            "wpfy update",
            [
                f"installed: {current_version}",
                f"latest published: {latest}",
                "status: installed and published versions differ",
                "hint: use --force to run pip upgrade",
            ],
        ))

    if force:
        if current_version == latest:
            return CommandResult(_render_summary("wpfy update", [f"installed: {current_version}", "status: already latest"]))
        proc = subprocess.run(
            [sys.executable, "-m", "pip", "install", "--upgrade", "wpfy"],
            check=False, capture_output=True, text=True,
        )
        if proc.returncode != 0:
            err = proc.stderr.strip() or proc.stdout.strip() or "pip install failed"
            return CommandResult(_render_summary("wpfy update", [f"version: {current_version}", f"FAIL upgrade failed: {err}"]), exit_code=proc.returncode)
        return CommandResult(_render_summary(
            "wpfy update",
            [
                f"installed before command: {current_version}",
                f"latest published: {latest}",
                "status: pip upgrade command completed",
            ],
        ))

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
    parser.add_argument("--w3tc", action="store_true")
    parser.add_argument("--wpfastest", action="store_true")
    parser.add_argument("--flyingpress", action="store_true")
    parser.add_argument("--wpsubdir", action="store_true")
    parser.add_argument("--wpsubdomain", action="store_true")
    parser.add_argument("-le", "--letsencrypt", nargs="?", const="default", choices=LETSENCRYPT_MODES)
    parser.add_argument("--dns", choices=DNS_PROVIDERS)
    parser.add_argument(
        "--proxied",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="force proxied (HTTP-01) mode on/off; default auto-detects Cloudflare",
    )
    parser.add_argument("--user", dest="wp_user", help="WordPress administrator username")
    parser.add_argument("--email", dest="wp_email", help="WordPress administrator email")
    parser.add_argument(
        "--pass",
        dest="wp_password",
        nargs="?",
        const="prompt",
        help="WordPress administrator password: '-' for stdin, or prompt",
    )


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
    set_parser.add_argument(
        "--allow-insecure",
        action="store_true",
        help="allow plaintext HTTP S3 transport; exposes backup contents and SigV4 credentials",
    )
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


def add_metrics_parser(subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    parser = _add_parser(
        subparsers,
        "metrics",
        help="Sample, query, or prune host and per-site metrics.",
    )
    metrics_subparsers = parser.add_subparsers(dest="metrics_command")

    sample = metrics_subparsers.add_parser("sample", help="record one host and per-site sample")
    sample.set_defaults(handler=handle_metrics)

    show = metrics_subparsers.add_parser("show", help="show samples for one scope and range")
    show.add_argument("--scope", default=metrics.HOST_SCOPE, help="host or a managed domain")
    show.add_argument("--range", dest="range_key", choices=metrics.RANGES, default="1h")
    show.set_defaults(handler=handle_metrics)

    prune_parser = metrics_subparsers.add_parser("prune", help="delete samples older than retention")
    prune_parser.set_defaults(handler=handle_metrics)


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
        touched = ensure_site_scaffold(definition)
        if definition.flavor not in WORDPRESS_FLAVORS:
            return touched, None
        cache_result = site_cache.render_cache_nginx(domain)
        if cache_result.exit_code != 0:
            return touched, CommandResult(cache_result.message, exit_code=cache_result.exit_code)
        return touched, None
    except (OSError, ValueError) as exc:
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
    if result.cache_message:
        lines.append(f"cache: {result.cache_message}")
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
    parser.add_argument("--memory-limit", dest="php_memory_limit")
    parser.add_argument("--max-execution-time", dest="php_max_execution_time")
    parser.add_argument("--max-input-time", dest="php_max_input_time")
    parser.add_argument("--max-input-vars", dest="php_max_input_vars")
    parser.add_argument("--upload-size", dest="php_upload_max_size")
    parser.add_argument("--reset-php", action="store_true")
    parser.add_argument("--wpfc", action="store_true")
    parser.add_argument("--wpredis", action="store_true")
    parser.add_argument("--wpsubdir", action="store_true")
    parser.add_argument("--wpsubdomain", action="store_true")
    parser.add_argument("-le", "--letsencrypt", nargs="?", const="default", default=None, choices=LETSENCRYPT_MODES)
    parser.add_argument("--dns", choices=DNS_PROVIDERS)
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


def _required_secret(
    read_stdin: bool,
    *,
    prompt: str,
    stdin_error: str,
    tty_error: str,
    empty_error: str,
) -> tuple[str | None, CommandResult | None]:
    if read_stdin:
        secret = sys.stdin.readline().rstrip("\r\n")
        if not secret:
            return None, CommandResult(stdin_error, exit_code=2)
        return secret, None
    if not sys.stdin.isatty():
        return None, CommandResult(tty_error, exit_code=2)
    secret = getpass.getpass(prompt)
    if not secret:
        return None, CommandResult(empty_error, exit_code=2)
    return secret, None


def _config_password(args: argparse.Namespace) -> tuple[str | None, CommandResult | None]:
    if not (getattr(args, "password_stdin", False) or getattr(args, "password", False)):
        return None, None
    return _required_secret(
        getattr(args, "password_stdin", False),
        prompt="WordPress admin password: ",
        stdin_error="password required on stdin",
        tty_error="password prompt requires a TTY; use --password-stdin for scripts",
        empty_error="password cannot be empty",
    )


def _has_config_mutation(args: argparse.Namespace) -> bool:
    return _has_php_config_mutation(args) or _has_non_php_config_mutation(args)


def _has_non_php_config_mutation(args: argparse.Namespace) -> bool:
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


def _has_php_config_mutation(args: argparse.Namespace) -> bool:
    return any((
        args.php_memory_limit is not None,
        args.php_max_execution_time is not None,
        args.php_max_input_time is not None,
        args.php_max_input_vars is not None,
        args.php_upload_max_size is not None,
        args.reset_php,
    ))


def _php_config_command_result(result: site_configuration.ConfigurationResult) -> CommandResult:
    change_text = ", ".join(result.changes) if result.changes else "no changes detected"
    lines = [_section("PHP settings"), f"changes: {change_text}"]
    lines.append(_step_line("runtime", result.runtime))
    if result.message and result.exit_code != 0:
        lines.append(f"details: {result.message}")
    return CommandResult("\n".join(lines), exit_code=result.exit_code)


def handle_config(args: argparse.Namespace) -> CommandResult:
    site_error = _require_existing_site(args.domain)
    if site_error:
        return site_error

    if _has_php_config_mutation(args) and _has_non_php_config_mutation(args):
        return CommandResult(
            "PHP ini settings cannot be combined with PHP version, flavor, SSL, or password changes",
            exit_code=2,
        )

    if _has_php_config_mutation(args):
        try:
            result = site_configuration.update_php_settings(
                args.domain,
                php_memory_limit=args.php_memory_limit,
                php_max_execution_time=args.php_max_execution_time,
                php_max_input_time=args.php_max_input_time,
                php_max_input_vars=args.php_max_input_vars,
                php_upload_max_size=args.php_upload_max_size,
                reset=args.reset_php,
            )
        except ValueError as exc:
            return CommandResult(str(exc), exit_code=2)
        return _php_config_command_result(result)

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
                    f"page cache: {definition.page_cache}",
                    f"object cache: {definition.object_cache}",
                    f"php: {definition.php_version}",
                    f"memory limit: {definition.php_memory_limit}",
                    f"max execution time: {definition.php_max_execution_time}",
                    f"max input time: {definition.php_max_input_time}",
                    f"max input vars: {definition.php_max_input_vars}",
                    f"upload size: {definition.php_upload_max_size}",
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
    disk_parser.add_argument("--warn", type=float, default=DISK_THRESHOLDS[0], help="warning threshold percentage")
    disk_parser.add_argument("--fail", type=float, default=DISK_THRESHOLDS[1], help="failure threshold percentage")
    disk_parser.set_defaults(health_target="disk")

    load_parser = _add_parser(health_subparsers, "load", help="Check host load average per CPU.")
    load_parser.add_argument("--warn", type=float, default=LOAD_THRESHOLDS[0], help="warning threshold per CPU")
    load_parser.add_argument("--fail", type=float, default=LOAD_THRESHOLDS[1], help="failure threshold per CPU")
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


def _healthcheck_app_domain(domain: str) -> CommandResult:
    site_error = _require_existing_site(domain)
    if site_error:
        return site_error
    health = site_health(domain)
    ok = app_health_ok(health.status, health.bootstrap_ready, health.runtime_ready)
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
        _healthcheck_disk("/", *DISK_THRESHOLDS),
        _healthcheck_load(*LOAD_THRESHOLDS),
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


def add_telemetry_parser(subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    parser = _add_parser(subparsers, "telemetry", help="Inspect or control anonymous usage telemetry.")
    commands = parser.add_subparsers(dest="telemetry_command")
    for command in ("status", "enable", "disable"):
        _add_parser(commands, command, help=f"{command.title()} anonymous usage telemetry.").set_defaults(
            handler=handle_telemetry,
        )


def handle_telemetry(args: argparse.Namespace) -> CommandResult:
    command = args.telemetry_command
    if command == "enable":
        telemetry.set_enabled(True)
        return CommandResult("anonymous usage telemetry enabled")
    if command == "disable":
        telemetry.set_enabled(False)
        return CommandResult("anonymous usage telemetry disabled")
    if command == "status":
        current = telemetry.status()
        lines = [
            _section("telemetry status"),
            f"stored: {'enabled' if current['stored_enabled'] else 'disabled'}",
            f"environment override: {'disabled' if current['environment_override'] else 'none'}",
            f"effective: {'enabled' if current['effective_enabled'] else 'disabled'}",
            f"endpoint: {'configured' if current['endpoint_configured'] else 'not configured (nothing is sent)'}",
            f"last sent: {current['last_sent_at'] or 'never'}",
            "payload:",
            json.dumps(current["payload"], indent=2, sort_keys=True),
        ]
        return CommandResult("\n".join(lines))
    return CommandResult("telemetry command required", exit_code=2)


def add_panel_parser(subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    parser = _add_parser(
        subparsers,
        "panel",
        help="Serve or administer the local browser control panel.",
        epilog=(
            "The panel binds to a loopback address.\n"
            "Remote access: ssh -L 8642:127.0.0.1:8642 <server>, then open the URL locally.\n"
        ),
    )
    parser.add_argument("--host", default="127.0.0.1", help="loopback address to bind")
    parser.add_argument("--port", type=int, default=panel.DEFAULT_PANEL_PORT, help="port to listen on")
    parser.add_argument(
        "--token",
        help="access token used only while no panel users exist; exposes the value in "
             "the process table, prefer --token-file or WPFY_PANEL_TOKEN",
    )
    parser.add_argument(
        "--token-file",
        help="read the access token from a file, keeping it out of the process table",
    )
    parser.add_argument("--edge-service", action="store_true", help=argparse.SUPPRESS)
    commands = parser.add_subparsers(dest="panel_command")

    expose = _add_parser(commands, "expose", help="Publish or disable the panel through Traefik.")
    exposure_action = expose.add_mutually_exclusive_group(required=True)
    exposure_action.add_argument("--domain")
    exposure_action.add_argument("--disable", action="store_true")
    exposure_action.add_argument("--status", action="store_true")
    expose.add_argument("--confirm", help="typed confirmation; must exactly match --domain")
    expose.add_argument("--port", type=int, default=panel.DEFAULT_PANEL_PORT)
    expose.set_defaults(handler=handle_panel_exposure)

    service = _add_parser(commands, "service", help="Manage the edge-bound panel systemd service.")
    service_commands = service.add_subparsers(dest="panel_service_command")
    install = _add_parser(service_commands, "install", help="Install and start the panel service.")
    install.add_argument("--port", type=int, default=panel.DEFAULT_PANEL_PORT)
    install.set_defaults(handler=handle_panel_exposure)
    _add_parser(service_commands, "remove", help="Stop and remove the panel service.").set_defaults(
        handler=handle_panel_exposure,
    )

    users = _add_parser(commands, "user", help="Manage panel users and site assignments.")
    user_commands = users.add_subparsers(dest="panel_user_command")

    add = _add_parser(user_commands, "add", help="Add a panel user.")
    add.add_argument("username")
    add.add_argument("--role", required=True, choices=sorted(panel_auth.ROLES))
    add.add_argument("--site", action="append", default=[], dest="sites")
    add.add_argument("--password-stdin", action="store_true")
    add.set_defaults(handler=handle_panel_auth)

    remove = _add_parser(user_commands, "remove", help="Remove a panel user.")
    remove.add_argument("username")
    remove.set_defaults(handler=handle_panel_auth)

    _add_parser(user_commands, "list", help="List panel users.").set_defaults(handler=handle_panel_auth)

    password = _add_parser(user_commands, "set-password", help="Set a panel user password.")
    password.add_argument("username")
    password.add_argument("--password-stdin", action="store_true")
    password.set_defaults(handler=handle_panel_auth)

    role = _add_parser(user_commands, "set-role", help="Set a panel user role.")
    role.add_argument("username")
    role.add_argument("role", choices=sorted(panel_auth.ROLES))
    role.set_defaults(handler=handle_panel_auth)

    assign = _add_parser(user_commands, "assign-site", help="Assign a site to a panel user.")
    assign.add_argument("username")
    assign.add_argument("domain")
    assign.set_defaults(handler=handle_panel_auth)

    revoke = _add_parser(user_commands, "revoke-site", help="Revoke a panel user's site assignment.")
    revoke.add_argument("username")
    revoke.add_argument("domain")
    revoke.set_defaults(handler=handle_panel_auth)

    totp = _add_parser(commands, "totp", help="Manage a panel user's TOTP factor.")
    totp_commands = totp.add_subparsers(dest="panel_totp_command")
    for action in ("enable", "disable"):
        child = _add_parser(totp_commands, action, help=f"{action.title()} TOTP for a panel user.")
        child.add_argument("username")
        child.set_defaults(handler=handle_panel_auth)

    parser.set_defaults(handler=handle_panel)


def _panel_user_password(args: argparse.Namespace) -> tuple[str | None, CommandResult | None]:
    return _required_secret(
        getattr(args, "password_stdin", False),
        prompt="Panel password: ",
        stdin_error="panel password required on stdin",
        tty_error="panel password prompt requires a TTY; use --password-stdin for scripts",
        empty_error="panel password cannot be empty",
    )


def handle_panel_auth(args: argparse.Namespace) -> CommandResult:
    try:
        if args.panel_command == "user":
            command = args.panel_user_command
            if command == "list":
                users = panel_auth.list_users()
                if not users:
                    return CommandResult("no panel users configured")
                lines = [_section("panel users")]
                for user in users:
                    sites = ", ".join(user["sites"]) or "none"
                    totp = "enabled" if user["totp_enabled"] else "disabled"
                    lines.append(f"{user['username']}\trole={user['role']}\tsites={sites}\ttotp={totp}")
                return CommandResult("\n".join(lines))
            if command in {"add", "set-password"}:
                password, error = _panel_user_password(args)
                if error:
                    return error
                if command == "add":
                    panel_auth.add_user(args.username, password, role=args.role, sites=args.sites)
                    return CommandResult(f"panel user added: {args.username}")
                panel_auth.set_password(args.username, password)
                return CommandResult(f"panel password updated: {args.username}")
            if command == "remove":
                panel_auth.remove_user(args.username)
                return CommandResult(f"panel user removed: {args.username}")
            if command == "set-role":
                panel_auth.set_role(args.username, args.role)
                return CommandResult(f"panel role updated: {args.username} -> {args.role}")
            if command == "assign-site":
                panel_auth.assign_site(args.username, args.domain)
                return CommandResult(f"panel site assigned: {args.username} -> {args.domain}")
            if command == "revoke-site":
                panel_auth.revoke_site(args.username, args.domain)
                return CommandResult(f"panel site revoked: {args.username} -> {args.domain}")
            return CommandResult("panel user command required", exit_code=2)
        if args.panel_command == "totp":
            if args.panel_totp_command == "enable":
                if not sys.stdin.isatty():
                    return CommandResult(
                        "TOTP enrollment requires the browser setup/account panel or an interactive TTY",
                        exit_code=2,
                    )
                secret, uri = panel_auth.begin_totp_enrollment(args.username)
                print(_render_summary(
                    "panel TOTP enrollment",
                    [f"username: {args.username}", f"secret (shown once): {secret}", f"uri: {uri}"],
                ))
                code = input("Authenticator code: ").strip()
                panel_auth.complete_totp_enrollment(args.username, code)
                return CommandResult(f"panel TOTP enabled: {args.username}")
            if args.panel_totp_command == "disable":
                panel_auth.disable_totp(args.username)
                return CommandResult(f"panel TOTP disabled: {args.username}")
            return CommandResult("panel TOTP command required", exit_code=2)
    except (OSError, ValueError) as exc:
        return CommandResult(str(exc), exit_code=2)
    return CommandResult("panel command required", exit_code=2)


def handle_panel_exposure(args: argparse.Namespace) -> CommandResult:
    try:
        if args.panel_command == "expose":
            if args.status:
                status = panel_exposure.exposure_status()
                lines = [
                    _section("panel exposure status"),
                    f"router: {'configured' if status['router_present'] else 'disabled'}",
                    f"recognised: {_bool_text(status['recognised'])}",
                    f"domain: {status['domain'] or 'unknown'}",
                    f"service: {'installed' if status['service_installed'] else 'not installed'}",
                ]
                if status["router_present"] and not status["service_installed"]:
                    lines.append("next: wpfy panel service install is required before the public panel is ready")
                return CommandResult("\n".join(lines))
            if args.disable:
                result = panel_exposure.disable()
            else:
                confirmation = args.confirm
                if confirmation is None:
                    if not sys.stdin.isatty():
                        return CommandResult(
                            "typed confirmation required; pass --confirm with the exact panel domain",
                            exit_code=2,
                        )
                    confirmation = input(f"Type {args.domain} to expose the panel: ")
                result = panel_exposure.expose(args.domain, confirm=confirmation, port=args.port)
        elif args.panel_command == "service":
            if args.panel_service_command == "install":
                result = panel_exposure.install_service(panel_exposure.edge_bind_address(), args.port)
            elif args.panel_service_command == "remove":
                result = panel_exposure.remove_service()
            else:
                return CommandResult("panel service command required", exit_code=2)
        else:
            return CommandResult("panel exposure command required", exit_code=2)
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        return CommandResult(str(exc), exit_code=2)
    return CommandResult(result.message, exit_code=result.exit_code)


def resolve_panel_token(
    args: argparse.Namespace, environ: dict | None = None,
) -> tuple[str, str | None]:
    """Resolve the panel token from a file, environment, or generated value.

    Highest precedence first: --token-file, WPFY_PANEL_TOKEN, generated.
    Raw --token values are refused because a running panel leaves them exposed
    in the process command line.
    """
    environ = os.environ if environ is None else environ

    token_file = getattr(args, "token_file", None)
    if token_file:
        value = Path(token_file).read_text(encoding="utf-8").strip()
        if not value:
            raise ValueError(f"panel token file is empty: {token_file}")
        return value, None

    from_env = str(environ.get("WPFY_PANEL_TOKEN", "")).strip()
    if from_env:
        return from_env, None

    if getattr(args, "token", None):
        raise ValueError("raw --token values are not accepted; use --token-file or WPFY_PANEL_TOKEN")

    return panel.generate_panel_token(), None


def handle_panel(args: argparse.Namespace) -> CommandResult:
    try:
        token, token_warning = resolve_panel_token(args)
    except (OSError, ValueError) as exc:
        return CommandResult(f"panel token could not be read: {exc}", exit_code=2)
    if token_warning:
        print(token_warning, file=sys.stderr)
    config = panel.PanelConfig(host=args.host, port=args.port, token=token, edge_bind=args.edge_service)
    try:
        server = panel.make_panel_server(config)
    except ValueError as exc:
        return CommandResult(str(exc), exit_code=2)
    except OSError as exc:
        return CommandResult(f"panel could not bind {args.host}:{args.port}: {exc}", exit_code=2)

    actual_port = server.server_address[1]
    if args.edge_service:
        domain = panel_exposure.exposure_status().get("domain") or "configured panel domain"
        summary = [
            f"listening: http://{args.host}:{actual_port}/",
            f"open: https://{domain}/",
            "sign in with a configured panel user; press Ctrl+C to stop",
        ]
    else:
        access = (
            "sign in with a configured panel user; press Ctrl+C to stop"
            if panel_auth.login_required()
            else "the URL carries a one-time access token; press Ctrl+C to stop"
        )
        summary = [
            f"listening: http://{args.host}:{actual_port}/",
            f"open: {panel.panel_url(config, actual_port)}",
            access,
        ]
    print(_render_summary("wpfy panel", summary), flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return CommandResult("panel stopped")


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


def handle_utility_htpasswd(args: argparse.Namespace) -> CommandResult:
    username = args.username.strip()
    if not username or not site_security._safe_htpasswd_username(username):
        return CommandResult("invalid username: use letters, digits, '_', '.', '@', or '-'", exit_code=2)
    generated = not args.password_stdin
    if generated:
        password = _generate_password(24, True)
    else:
        password = sys.stdin.readline().rstrip("\r\n")
        if not password:
            return CommandResult("password required on stdin", exit_code=2)
    try:
        hashed_password, _scheme = site_security._htpasswd_hash(password)
    except RuntimeError as exc:
        return CommandResult(f"failed to generate htpasswd credential: {exc}", exit_code=3)
    htpasswd = f"{username}:{hashed_password}"
    if generated:
        return CommandResult("\n".join([f"username: {username}", f"password: {password}", f"htpasswd: {htpasswd}"]))
    return CommandResult(f"htpasswd: {htpasswd}")


def _database_command_result(result: site_database.DatabaseResult) -> CommandResult:
    lines = [result.message] if result.message else []
    if result.one_time_password:
        lines.append(f"generated password (shown once): {result.one_time_password}")
    return CommandResult("\n".join(lines), exit_code=result.exit_code)


def _password_argument(
    value: str | None,
    *,
    password_name: str = "database password",
    prompt: str = "Database password: ",
) -> tuple[str | None, CommandResult | None]:
    if value is None:
        return None, None
    if value == "-":
        password = sys.stdin.readline().rstrip("\r\n")
        if not password:
            return None, CommandResult(f"{password_name} required on stdin", exit_code=2)
        return password, None
    if value == "prompt":
        if not sys.stdin.isatty():
            return None, CommandResult(f"{password_name} prompt requires a TTY; use --password -", exit_code=2)
        password = getpass.getpass(prompt)
        if not password:
            return None, CommandResult(f"{password_name} cannot be empty", exit_code=2)
        return password, None
    return None, CommandResult("use --password - or --password prompt; raw passwords are not accepted", exit_code=2)


def handle_db(args: argparse.Namespace) -> CommandResult:
    domain = args.domain
    command = args.db_command
    try:
        if command == "list":
            return _database_command_result(site_database.list_databases(domain))
        if command == "users":
            return _database_command_result(site_database.list_users(domain))
        if command == "create":
            return _database_command_result(site_database.create_database(domain, args.name))
        if command == "drop":
            return _database_command_result(site_database.drop_database(domain, args.name))
        if command == "user-drop":
            return _database_command_result(site_database.drop_user(domain, args.user))
        if command == "grant":
            return _database_command_result(site_database.grant(domain, args.user, args.database))
        if command == "user-add":
            password, error = _password_argument(args.password)
            if error:
                return error
            return _database_command_result(
                site_database.create_user(domain, args.user, password=password, grants=args.database),
            )
        if command == "user-password":
            password, error = _password_argument(args.password)
            if error:
                return error
            return _database_command_result(site_database.set_user_password(domain, args.user, password=password))
        if command == "adminer":
            result = site_configuration.configure_adminer(
                domain,
                enabled=args.adminer_action == "on",
                port=args.port,
            )
            return CommandResult(result.message, exit_code=result.exit_code)
    except (ValueError, FileNotFoundError) as exc:
        return CommandResult(str(exc), exit_code=2)
    return CommandResult("database command required", exit_code=2)


def add_db_parser(subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    parser = _add_parser(subparsers, "db", help="Manage per-site databases and database users.")
    parser.add_argument("domain")
    commands = parser.add_subparsers(dest="db_command")
    _add_parser(commands, "list", help="List non-system databases.").set_defaults(handler=handle_db)
    _add_parser(commands, "users", help="List scoped database users.").set_defaults(handler=handle_db)

    for name, help_text in (("create", "Create a database."), ("drop", "Drop a database.")):
        child = _add_parser(commands, name, help=help_text)
        child.add_argument("name")
        child.set_defaults(handler=handle_db)

    user_add = _add_parser(commands, "user-add", help="Create a scoped database user.")
    user_add.add_argument("user")
    user_add.add_argument("--password", nargs="?", const="prompt", help="password, '-' for stdin, or prompt")
    user_add.add_argument("--database")
    user_add.set_defaults(handler=handle_db)

    user_drop = _add_parser(commands, "user-drop", help="Drop a database user.")
    user_drop.add_argument("user")
    user_drop.set_defaults(handler=handle_db)

    user_password = _add_parser(commands, "user-password", help="Set a database user password.")
    user_password.add_argument("user")
    user_password.add_argument("--password", nargs="?", const="prompt", help="password, '-' for stdin, or prompt")
    user_password.set_defaults(handler=handle_db)

    grant_parser = _add_parser(commands, "grant", help="Grant a user access to one database.")
    grant_parser.add_argument("user")
    grant_parser.add_argument("database")
    grant_parser.set_defaults(handler=handle_db)

    adminer = _add_parser(commands, "adminer", help="Enable or disable the loopback-only Adminer service.")
    adminer.add_argument("adminer_action", choices=("on", "off"))
    adminer.add_argument("--port", type=int)
    adminer.set_defaults(handler=handle_db)


def handle_site_security(args: argparse.Namespace) -> CommandResult:
    try:
        if args.security_command == "show":
            return CommandResult(json.dumps(site_security.load_security(args.domain), indent=2, sort_keys=True))
        if args.security_command == "deny-ip":
            operation = (
                site_security.add_deny_ip
                if args.security_action == "add"
                else site_security.remove_deny_ip
            )
            result = operation(args.domain, args.cidr)
        elif args.security_command == "ua-block":
            operation = (
                site_security.add_ua_block
                if args.security_action == "add"
                else site_security.remove_ua_block
            )
            result = operation(args.domain, args.pattern)
        elif args.security_command == "basic-auth":
            enabled = args.security_action == "on"
            password = None
            if enabled and args.password_stdin:
                password = sys.stdin.readline().rstrip("\r\n")
                if not password:
                    return CommandResult("basic-auth password required on stdin", exit_code=2)
            elif enabled and sys.stdin.isatty():
                password = getpass.getpass("Basic-auth password (leave empty to generate): ")
                password = password or None
            result = site_security.set_basic_auth(
                args.domain,
                enabled=enabled,
                username=args.username,
                password=password,
            )
        elif args.security_command == "login-rate-limit":
            result = site_security.set_login_rate_limit(args.domain, args.security_action == "on")
        elif args.security_command == "fail2ban":
            result = site_security.set_fail2ban(args.domain, args.security_action == "on")
        elif args.security_command == "cf-only":
            enabled = args.security_action == "on"
            if enabled:
                preflight = site_security.security_preflight(args.domain, {"cloudflare_only": True})
                if preflight.warnings and not args.force:
                    return CommandResult(
                        "\n".join(["WARNING: " + warning for warning in preflight.warnings])
                        + "\nre-run with --force to proceed",
                        exit_code=2,
                    )
                warning_prefix = "\n".join("WARNING: " + warning for warning in preflight.warnings)
            else:
                warning_prefix = ""
            result = site_security.set_cloudflare_only(args.domain, enabled)
            if warning_prefix:
                result = site_security.SecurityResult(
                    result.exit_code,
                    warning_prefix + "\n" + result.message,
                    result.changed,
                    result.one_time_password,
                )
        else:
            return CommandResult("security command required", exit_code=2)
    except (ValueError, TypeError, FileNotFoundError, OSError, RuntimeError) as exc:
        return CommandResult(str(exc), exit_code=2)
    message = result.message
    if result.one_time_password:
        message += f"\ngenerated password (shown once): {result.one_time_password}"
    return CommandResult(message, exit_code=result.exit_code)


def add_site_security_parser(site_subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    parser = _add_parser(site_subparsers, "security", help="Manage per-site nginx access controls.")
    parser.add_argument("domain")
    commands = parser.add_subparsers(dest="security_command")
    _add_parser(commands, "show", help="Show the persisted per-site security state.").set_defaults(
        handler=handle_site_security,
    )

    deny = _add_parser(commands, "deny-ip", help="Add or remove a denied client CIDR.")
    deny_actions = deny.add_subparsers(dest="security_action")
    for action in ("add", "remove"):
        child = _add_parser(deny_actions, action, help=f"{action.title()} a denied client CIDR.")
        child.add_argument("cidr")
        child.set_defaults(handler=handle_site_security)

    user_agent = _add_parser(commands, "ua-block", help="Add or remove a blocked user-agent pattern.")
    user_agent_actions = user_agent.add_subparsers(dest="security_action")
    for action in ("add", "remove"):
        child = _add_parser(user_agent_actions, action, help=f"{action.title()} a user-agent pattern.")
        child.add_argument("pattern")
        child.set_defaults(handler=handle_site_security)

    basic_auth = _add_parser(commands, "basic-auth", help="Enable or disable per-site HTTP basic auth.")
    basic_auth_actions = basic_auth.add_subparsers(dest="security_action")
    basic_on = _add_parser(basic_auth_actions, "on", help="Enable basic auth; prompt or read the password.")
    basic_on.add_argument("--username", required=True)
    basic_on.add_argument("--password-stdin", action="store_true", help="read the password from stdin")
    basic_on.set_defaults(handler=handle_site_security)
    basic_off = _add_parser(basic_auth_actions, "off", help="Disable basic auth and revoke the stored hash.")
    basic_off.set_defaults(handler=handle_site_security, username=None, password_stdin=False)

    login_rate_limit = _add_parser(
        commands, "login-rate-limit", help="Enable or disable WordPress wp-login.php rate limiting.",
    )
    login_rate_limit_actions = login_rate_limit.add_subparsers(dest="security_action")
    for action in ("on", "off"):
        child = _add_parser(login_rate_limit_actions, action, help=f"Turn WordPress login rate limiting {action}.")
        child.set_defaults(handler=handle_site_security)

    fail2ban = _add_parser(commands, "fail2ban", help="Enable or disable WordPress fail2ban protection.")
    fail2ban_actions = fail2ban.add_subparsers(dest="security_action")
    for action in ("on", "off"):
        child = _add_parser(fail2ban_actions, action, help=f"Turn WordPress fail2ban protection {action}.")
        child.set_defaults(handler=handle_site_security)

    cf_only = _add_parser(commands, "cf-only", help="Enforce Cloudflare-only access at Traefik.")
    cf_actions = cf_only.add_subparsers(dest="security_action")
    cf_on = _add_parser(cf_actions, "on", help="Enable the Cloudflare edge allow list.")
    cf_on.add_argument("--force", action="store_true", help="proceed despite lockout preflight warnings")
    cf_on.set_defaults(handler=handle_site_security)
    cf_off = _add_parser(cf_actions, "off", help="Remove the Cloudflare edge allow list.")
    cf_off.set_defaults(handler=handle_site_security, force=False)


def handle_site_nginx(args: argparse.Namespace) -> CommandResult:
    try:
        if args.nginx_command == "show":
            result = get_nginx_custom(args.domain)
        elif args.nginx_command == "validate":
            result = validate_nginx_custom(args.domain)
        elif args.nginx_command == "reset":
            result = set_nginx_custom(args.domain, "")
        elif args.nginx_command == "set":
            if not args.stdin:
                return CommandResult("nginx set requires --stdin", exit_code=2)
            result = set_nginx_custom(args.domain, sys.stdin.read())
        else:
            return CommandResult("nginx command required", exit_code=2)
    except (ValueError, FileNotFoundError) as exc:
        return CommandResult(str(exc), exit_code=2)
    return CommandResult(result.message, exit_code=result.exit_code)


def add_site_nginx_parser(site_subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    parser = _add_parser(site_subparsers, "nginx", help="Inspect or safely update the generated vhost include.")
    parser.add_argument("domain")
    commands = parser.add_subparsers(dest="nginx_command")
    commands_info = (
        ("show", "Show the operator-owned nginx snippet."),
        ("validate", "Validate the current snippet."),
        ("reset", "Replace the snippet with an empty validated file."),
    )
    for name, help_text in commands_info:
        child = _add_parser(commands, name, help=help_text)
        child.set_defaults(handler=handle_site_nginx)
    set_parser = _add_parser(commands, "set", help="Read a snippet from stdin and validate it before install.")
    set_parser.add_argument("--stdin", action="store_true")
    set_parser.set_defaults(handler=handle_site_nginx)


def handle_site_php(args: argparse.Namespace) -> CommandResult:
    try:
        result = validate_php_custom(args.domain)
    except ValueError as exc:
        return CommandResult(str(exc), exit_code=2)
    return CommandResult(result.message, exit_code=result.exit_code)


def add_site_php_parser(site_subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    parser = _add_parser(site_subparsers, "php", help="Inspect PHP operator overrides.")
    parser.add_argument("domain")
    commands = parser.add_subparsers(dest="php_command")
    validate = _add_parser(commands, "validate", help="Validate php/custom.ini with the site's PHP image.")
    validate.set_defaults(handler=handle_site_php)


def handle_site_files(args: argparse.Namespace) -> CommandResult:
    try:
        if args.site_files_command == "ls":
            result = files.list_files(args.domain, args.path)
            lines = [
                f"{entry['mode']}\t{entry['type']}\t{entry['size']}\t{entry['modified']}\t{ascii(entry['name'])[1:-1]}"
                for entry in result["entries"]
            ]
            return CommandResult("\n".join(lines))
        if args.site_files_command == "cat":
            return CommandResult(files.read_file(args.domain, args.path)["content"], raw_output=True)
        if args.site_files_command == "put":
            source = Path(args.content_file)
            with source.open("rb") as stream:
                result = files.upload_file(args.domain, args.path, stream, os.fstat(stream.fileno()).st_size)
            return CommandResult(f"file written: {result['path']}")
        if args.site_files_command == "rm":
            result = files.delete_path(args.domain, args.path, confirm=args.confirm)
            return CommandResult(f"file removed: {result['path']}")
    except (OSError, TypeError, ValueError) as exc:
        return CommandResult(str(exc), exit_code=2)
    return CommandResult("site files command required", exit_code=2)


def add_site_files_parser(subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    parser = _add_parser(subparsers, "files", help="Manage files inside the site's app directory.")
    parser.add_argument("domain")
    commands = parser.add_subparsers(dest="site_files_command")

    list_parser = _add_parser(commands, "ls", help="List files in the app directory.")
    list_parser.add_argument("path", nargs="?", default="")
    list_parser.set_defaults(handler=handle_site_files)

    cat_parser = _add_parser(commands, "cat", help="Read a text file within the editor size limit.")
    cat_parser.add_argument("path")
    cat_parser.set_defaults(handler=handle_site_files)

    put_parser = _add_parser(commands, "put", help="Write a host file into the app directory.")
    put_parser.add_argument("path")
    put_parser.add_argument("--content-file", required=True)
    put_parser.set_defaults(handler=handle_site_files)

    remove_parser = _add_parser(commands, "rm", help="Remove a file or directory from the app directory.")
    remove_parser.add_argument("path")
    remove_parser.add_argument("--confirm")
    remove_parser.set_defaults(handler=handle_site_files)


def handle_site_cron(args: argparse.Namespace) -> CommandResult:
    try:
        if args.site_cron_command == "list":
            jobs = site_cron.load_cron(args.domain)
            if not jobs:
                return CommandResult(_render_summary(f"site cron: {args.domain}", ["no cron jobs configured"]))
            lines = []
            for job in jobs:
                state = "enabled" if job["enabled"] else "disabled"
                lines.append(
                    f"{job['id']}\t{state}\t{job['schedule']}\tservice={job['service']}\t"
                    f"timeout={job['timeout']}\t{job['command']}"
                )
            return CommandResult(_render_summary(f"site cron: {args.domain}", lines))
        if args.site_cron_command == "add":
            job = site_cron.add_job(
                args.domain,
                schedule=args.schedule,
                command=args.command,
                service=args.service,
                timeout=args.timeout,
            )
            return CommandResult(f"cron job added: {job['id']}")
        if args.site_cron_command == "remove":
            site_cron.remove_job(args.domain, args.id)
            return CommandResult(f"cron job removed: {args.id}")
        if args.site_cron_command in {"enable", "disable"}:
            enabled = args.site_cron_command == "enable"
            site_cron.set_enabled(args.domain, args.id, enabled)
            return CommandResult(f"cron job {'enabled' if enabled else 'disabled'}: {args.id}")
        if args.site_cron_command == "run":
            result = site_cron.run_job(args.domain, args.id)
            line = f"cron job {args.id}: {result.outcome.upper()} duration={result.duration:.3f}s"
            return CommandResult(line, exit_code=result.exit_code)
    except (OSError, TypeError, ValueError) as exc:
        return CommandResult(str(exc), exit_code=2)
    return CommandResult("site cron command required", exit_code=2)


def add_site_cron_parser(subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    parser = _add_parser(
        subparsers,
        "cron",
        help="Manage scheduled commands inside this site's containers.",
    )
    parser.add_argument("domain")
    commands = parser.add_subparsers(dest="site_cron_command")

    list_parser = _add_parser(commands, "list", help="List the site's cron jobs.")
    list_parser.set_defaults(handler=handle_site_cron)

    add_parser = _add_parser(commands, "add", help="Add a scheduled container command.")
    add_parser.add_argument("--schedule", required=True)
    add_parser.add_argument("--command", required=True)
    add_parser.add_argument("--service", default="app")
    add_parser.add_argument("--timeout", type=int, default=site_cron.DEFAULT_TIMEOUT)
    add_parser.set_defaults(handler=handle_site_cron)

    for name in ("remove", "enable", "disable", "run"):
        child = _add_parser(commands, name, help=f"{name.capitalize()} one cron job.")
        child.add_argument("id")
        child.set_defaults(handler=handle_site_cron)


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
    ssl.add_argument("-le", "--letsencrypt", nargs="?", const="default", choices=LETSENCRYPT_MODES)
    ssl.add_argument("--dns", choices=DNS_PROVIDERS)
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

    add_site_files_parser(site_subparsers)
    add_site_cron_parser(site_subparsers)
    add_site_nginx_parser(site_subparsers)
    add_site_php_parser(site_subparsers)
    add_site_security_parser(site_subparsers)

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
    update.add_argument("--wpsc", action="store_true")
    update.add_argument("--wprocket", action="store_true")
    update.add_argument("--wpce", action="store_true")
    update.add_argument("--w3tc", action="store_true")
    update.add_argument("--wpfastest", action="store_true")
    update.add_argument("--flyingpress", action="store_true")
    update.add_argument("--wpredis", action="store_true")
    update.add_argument("-le", "--letsencrypt", nargs="?", const="default", default=None, choices=LETSENCRYPT_MODES)
    update.add_argument(
        "--proxied",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="force proxied (HTTP-01) mode on/off; default keeps the current setting",
    )
    update.add_argument("--password", nargs="?", const="prompt", help="password, '-' for stdin, or prompt")
    update.add_argument("--wpsubdir", action="store_true")
    update.add_argument("--wpsubdomain", action="store_true")
    update.add_argument("--dns", choices=DNS_PROVIDERS)
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

    acme_email = _add_parser(
        stack_subparsers,
        "acme-email",
        help="Set or show the shared ACME contact email.",
    )
    acme_email.add_argument("address", nargs="?")
    acme_email.set_defaults(handler=handle_stack_acme_email)

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
    parser.add_argument(
        "--password",
        nargs="?",
        const="prompt",
        help="custom SFTP password: '-' for stdin, or prompt (auto-generated if omitted)",
    )
    parser.set_defaults(handler=handle_sftp)


def handle_sftp(args: argparse.Namespace) -> CommandResult:
    domain = args.domain
    password, password_error = _password_argument(
        args.password,
        password_name="SFTP password",
        prompt="SFTP password: ",
    )
    if password_error:
        return password_error
    if args.enable:
        result = sftp.ensure_sftp_container(domain, password=password)
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

    log_events = _add_parser(
        log_subparsers,
        "events",
        help="Show recent wpfy operation events.",
    )
    log_events.add_argument("--domain")
    log_events.add_argument("--limit", type=int, default=200)
    log_events.set_defaults(handler=handle_log_events)


def handle_log_show(args: argparse.Namespace) -> CommandResult:
    domain = args.domain
    try:
        site_info(domain)
    except (FileNotFoundError, ValueError) as exc:
        return CommandResult(str(exc), exit_code=2)

    service_filter: list[str] = []
    if args.nginx:
        service_filter.append("web")
    if args.php:
        service_filter.append("app")
    if args.mysql:
        service_filter.append("db")

    result = site_logs(
        domain,
        services=tuple(service_filter),
        lines=args.lines,
        follow=args.follow,
    )
    return CommandResult(result.stdout or result.stderr, exit_code=result.exit_code)


def handle_log_cron(args: argparse.Namespace) -> CommandResult:
    result = cron.read_cron_log(args.lines)
    return CommandResult(result.message, exit_code=result.exit_code)


def handle_log_events(args: argparse.Namespace) -> CommandResult:
    rows = events.list_events(limit=args.limit, domain=args.domain)
    return CommandResult("\n".join(json.dumps(row, sort_keys=True) for row in rows))


def handle_log_reset(args: argparse.Namespace) -> CommandResult:
    domain = args.domain
    try:
        site_info(domain)
    except (FileNotFoundError, ValueError) as exc:
        return CommandResult(str(exc), exit_code=2)

    result = reset_site_logs(domain)
    if result.stop.exit_code != 0 or result.stop.skipped:
        return CommandResult(
            _render_summary("log reset", [f"domain: {domain}", f"runtime: FAIL {result.stop.message}"]),
            exit_code=result.exit_code,
        )
    if result.restart is None or result.restart.exit_code != 0 or result.restart.skipped:
        message = result.restart.message if result.restart is not None else "restart did not run"
        lines = [
            _section("log reset"),
            "runtime: OK stopped",
            f"restart: FAIL {message}",
        ]
        return CommandResult("\n".join(lines), exit_code=result.exit_code)

    lines = [
        _section("log reset"),
        f"domain: {domain}",
        "runtime: OK stopped",
        "restart: OK started",
    ]
    return CommandResult("\n".join(lines))


def make_site_handler(name: str):
    if name not in {"delete", "list", "info", "show", "status"}:
        raise ValueError(f"unsupported site handler: {name}")

    def handler(args: argparse.Namespace) -> CommandResult:
        domain = getattr(args, "domain", None)
        if name == "list":
            try:
                registry.sync_from_filesystem()
                sites = registry.list_sites()
            except (OSError, ValueError) as exc:
                return CommandResult(f"site list reconciliation failed: {exc}", exit_code=1)
            if not sites:
                return CommandResult(_render_summary("managed sites", ["no managed sites found"]))
            lines = [_section(f"managed sites ({len(sites)})")]
            for site in sites:
                ssl_status, _certificate = _site_ssl_observation(site)
                lines.append(
                    f"{site.get('domain', '?')}\t{site.get('flavor', '?')}\t"
                    f"ssl={ssl_status}\t"
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
            ssl_status, certificate = _site_ssl_observation(info)
            certificate_status = certificate.get("status", "unknown")
            issuer = certificate.get("issuer") or "unknown"
            certificate_line = f"certificate: {certificate_status}"
            if certificate_status == "issued":
                certificate_line += f"; issuer={issuer}"
            lines = [
                _section(f"site info: {info['domain']}"),
                f"domain: {info['domain']}",
                f"flavor: {info.get('flavor', 'unknown')}",
                f"path: {info['path']}",
                f"compose: {info['compose']}",
                f"env: {info['env']}",
                f"ssl: {ssl_status}",
                certificate_line,
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
            ssl_status, certificate = _site_ssl_observation(info)
            certificate_status = certificate.get("status", "unknown")
            lines = [
                _section(f"site status: {info['domain']}"),
                f"domain: {info['domain']}",
                f"flavor: {info.get('flavor', 'unknown')}",
                f"path: {info['path']}",
                f"compose: {info['compose']}",
                f"ssl: {ssl_status}",
                f"certificate: {certificate_status}",
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
                result = site_lifecycle.delete_site(site_lifecycle.DeleteSiteRequest(domain=domain, force=force))
            except site_lifecycle.SiteLifecycleError as exc:
                return CommandResult(str(exc), exit_code=exc.exit_code)
            if result.backup.exit_code != 0 or result.backup.skipped:
                return CommandResult(
                    _render_summary(
                        "site delete",
                        [
                            f"domain: {domain}",
                            _step_line("backup", result.backup),
                            "runtime: SKIP blocked by backup failure",
                            "files: kept",
                        ],
                    ),
                    exit_code=result.exit_code,
                )
            if result.runtime.exit_code != 0 or result.runtime.skipped:
                return CommandResult(
                    _render_summary(
                        "site delete",
                        [
                            f"domain: {domain}",
                            _step_line("backup", result.backup),
                            _step_line("runtime", result.runtime),
                            "files: kept",
                        ],
                    ),
                    exit_code=result.exit_code,
                )
            if result.removed:
                lines = [
                    _section("site deleted"),
                    f"domain: {domain}",
                    _step_line("backup", result.backup),
                    _step_line("runtime", result.runtime),
                    "files: removed",
                ]
                return CommandResult("\n".join(lines))
            return CommandResult(f"site not found: {domain}", exit_code=2)

        raise AssertionError(f"unhandled site handler: {name}")

    return handler


def handle_stack_install(args: argparse.Namespace) -> CommandResult:
    host_tools = tuple(flag for flag in stack.HOST_TOOLS if getattr(args, flag, False))
    helpers = tuple(flag for flag in stack.HELPER_IMAGES if getattr(args, flag, False))
    result = stack.install(stack.StackInstallRequest(
        install_all=getattr(args, "all", False),
        nginx=getattr(args, "nginx", False),
        php_version=getattr(args, "php", None),
        mysql=getattr(args, "mysql", False),
        mariadb=getattr(args, "mariadb", False),
        redis=getattr(args, "redis", False),
        wpcli=getattr(args, "wpcli", False),
        host_tools=host_tools,
        helpers=helpers,
        mysqltuner=getattr(args, "mysqltuner", False),
    ), progress=_progress)
    results = [
        _section("stack install"),
        *(f"{fact.name}: {fact.status} {fact.message}" for fact in result.facts),
    ]
    if not result.facts:
        results.append("nothing selected")
        results.append("hint: use --nginx, --php, --mysql, --redis, --wpcli, or --all")
    return CommandResult("\n".join(results), exit_code=result.exit_code)


def handle_stack_acme_email(args: argparse.Namespace) -> CommandResult:
    if args.address is not None:
        try:
            stack.traefik.set_acme_email(args.address)
        except ValueError as exc:
            return CommandResult(str(exc), exit_code=2)
    resolution = stack.traefik.resolve_acme_email()
    pending = stack.traefik.static_config_needs_apply()
    action = "Traefik restart required" if pending else "Traefik already has desired config"
    return CommandResult(
        _render_summary(
            "stack acme-email",
            [f"email: {resolution.email}", f"source: {resolution.source}", action],
        )
    )


def handle_stack_status(args: argparse.Namespace) -> CommandResult:
    results: list[str] = [_section("stack status")]

    status = stack.status()
    results.append(f"Traefik: {status.traefik.message}")
    if status.docker_error:
        results.append(f"Docker: FAIL {status.docker_error}")
    elif status.docker_version:
        results.append(f"Docker: {status.docker_version}")
    else:
        results.append("Docker: unavailable (is Docker installed and running?)")
    if status.images:
        results.append("Pulled wpfy images:")
        for line in status.images:
            results.append(f"  - {line}")
    elif status.images_error:
        results.append(f"Pulled wpfy images: FAIL {status.images_error}")
    else:
        results.append("Pulled wpfy images: none found")

    return CommandResult("\n".join(results), exit_code=status.exit_code)


def handle_stack_remove(args: argparse.Namespace) -> CommandResult:
    result = stack.remove()
    if result.skipped:
        return CommandResult(_render_summary("stack remove", [f"Traefik: SKIP {result.message}"]))
    if result.exit_code != 0:
        return CommandResult(
            _render_summary("stack remove", [f"Traefik: FAIL {result.message}"]),
            exit_code=result.exit_code,
        )
    return CommandResult(_render_summary("stack remove", [f"Traefik: OK {result.message}"]))


def handle_stack_upgrade(args: argparse.Namespace) -> CommandResult:
    result = stack.upgrade()
    lines = [_section("stack upgrade")]
    for fact in result.facts:
        lines.append(
            f"pull: {fact.message}"
            if fact.name == "pull"
            else f"{fact.name}: {fact.status} {fact.message}"
        )
    return CommandResult("\n".join(lines), exit_code=result.exit_code)


def handle_stack_purge(args: argparse.Namespace) -> CommandResult:
    result = stack.purge(force=getattr(args, "force", False))
    lines = [_section("stack purge")]
    for fact in result.facts:
        if fact.name == "compose project" and fact.status == "OK":
            lines.append("compose project removed")
        elif fact.name == "pulled images":
            lines.append(f"pulled images: {fact.message}")
        else:
            lines.append(f"{fact.name}: {fact.status} {fact.message}")
    return CommandResult("\n".join(lines), exit_code=result.exit_code)


def handle_stack_migrate(args: argparse.Namespace) -> CommandResult:
    return CommandResult(_render_summary("stack migrate", ["not implemented for Docker-first wpfy in v1"]))


def _site_cache_selection(args: argparse.Namespace) -> tuple[str, str, str] | CommandResult:
    base_flags = [
        flag for flag in ("html", "mysql", "wp", "wpsubdir", "wpsubdomain")
        if getattr(args, flag, False)
    ]
    page_flags = {
        "wpfc": "wpfc",
        "wpsc": "wp-super-cache",
        "wprocket": "wp-rocket",
        "wpce": "cache-enabler",
        "w3tc": "w3-total-cache",
        "wpfastest": "wp-fastest-cache",
        "flyingpress": "flying-press",
    }
    selected_page = [plugin for flag, plugin in page_flags.items() if getattr(args, flag, False)]
    if len(base_flags) > 1:
        return CommandResult("site type flags are mutually exclusive", exit_code=2)
    if len(selected_page) > 1:
        return CommandResult("page-cache flags are mutually exclusive", exit_code=2)
    if selected_page and base_flags and base_flags[0] in {"html", "mysql"}:
        return CommandResult("page-cache flags require a WordPress site", exit_code=2)
    page_cache = selected_page[0] if selected_page else "none"
    object_cache = "redis" if getattr(args, "wpredis", False) else "none"
    flavor = base_flags[0] if base_flags else "wp" if selected_page or object_cache == "redis" else "site"
    return flavor, page_cache, object_cache


def handle_site_create(args: argparse.Namespace) -> CommandResult:
    password, password_error = _password_argument(
        args.wp_password,
        password_name="WordPress admin password",
        prompt="WordPress admin password: ",
    )
    if password_error:
        return password_error
    args.wp_password = password

    selection = _site_cache_selection(args)
    if isinstance(selection, CommandResult):
        return selection
    flavor, page_cache, object_cache = selection
    request = site_lifecycle.CreateSiteRequest(
        domain=args.domain,
        flavor=flavor,
        page_cache=page_cache,
        object_cache=object_cache,
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
            page_cache=page_cache,
            object_cache=object_cache,
            cache_message=result.cache_message,
            created=result.created,
        ),
        exit_code=result.exit_code,
    )


def handle_site_update(args: argparse.Namespace) -> CommandResult:
    domain = args.domain
    password, password_error = _password_argument(
        args.password,
        password_name="WordPress admin password",
        prompt="WordPress admin password: ",
    )
    if password_error:
        return password_error

    page_flags = {
        "wpfc": "wpfc",
        "wpsc": "wp-super-cache",
        "wprocket": "wp-rocket",
        "wpce": "cache-enabler",
        "w3tc": "w3-total-cache",
        "wpfastest": "wp-fastest-cache",
        "flyingpress": "flying-press",
    }
    selected_page = [plugin for flag, plugin in page_flags.items() if getattr(args, flag, False)]
    if len(selected_page) > 1:
        return CommandResult("page-cache flags are mutually exclusive", exit_code=2)
    request = site_lifecycle.UpdateSiteRequest(
        domain=domain,
        php_version=args.php,
        page_cache=selected_page[0] if selected_page else None,
        object_cache="redis" if args.wpredis else None,
        wpredis=args.wpredis,
        wpsubdir=args.wpsubdir,
        wpsubdomain=args.wpsubdomain,
        letsencrypt=args.letsencrypt,
        dns_provider=getattr(args, "dns", None),
        proxied_override=getattr(args, "proxied", None),
        password=password,
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
        _section("ssl requested"),
        f"domain: {domain}",
        f"preflight: {result.preflight_message}",
        f"scaffold: {_site_count_summary(list(result.touched))}",
        _step_line("runtime", result.runtime),
        "certificate: requested; not yet verified",
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
        f"insecure HTTP: {'allowed' if config.allow_insecure else 'refused'}",
        "access key: configured",
        "secret key: configured",
    ]


def _load_backup_storage(profile: str | None = None) -> tuple[S3Config | None, CommandResult | None]:
    try:
        return load_s3_config(profile), None
    except RuntimeError as exc:
        return None, CommandResult(str(exc), exit_code=2)


def _secret_from_args(args: argparse.Namespace) -> tuple[str | None, CommandResult | None]:
    return _required_secret(
        getattr(args, "secret_key_stdin", False),
        prompt="S3 secret key: ",
        stdin_error="secret key required on stdin",
        tty_error="secret key prompt requires a TTY; use --secret-key-stdin for scripts",
        empty_error="secret key cannot be empty",
    )


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
            allow_insecure=args.allow_insecure,
        )
        try:
            path = write_s3_config(config, profile)
            stored = load_s3_config(profile)
        except RuntimeError as exc:
            return CommandResult(str(exc), exit_code=2)
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
        with tempfile.NamedTemporaryFile(prefix="wpfy-remote-restore-", suffix=".tar.gz", delete=False) as archive:
            archive_path = archive.name
        try:
            try:
                uploader.download_to_path(config, key, Path(archive_path))
            except (OSError, RuntimeError, ValueError) as exc:
                return CommandResult(
                    f"download: FAIL {redact_s3_secrets(str(exc), config)}",
                    exit_code=4,
                )
            try:
                result = restore_site(args.domain, archive_path)
            except (OSError, RuntimeError, ValueError) as exc:
                return CommandResult(
                    f"restore: FAIL {redact_s3_secrets(str(exc), config)}",
                    exit_code=4,
                )
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


def _metrics_sample_line(sample: metrics.Sample) -> str:
    return (
        f"{sample.timestamp} scope={sample.scope} cpu={sample.cpu_percent:.2f}% "
        f"memory={sample.memory_used}/{sample.memory_total} "
        f"disk={sample.disk_used}/{sample.disk_total} load1={sample.load1:.2f}"
    )


def handle_metrics(args: argparse.Namespace) -> CommandResult:
    try:
        if args.metrics_command == "sample":
            result = metrics.sample_once()
            lines = [_metrics_sample_line(sample) for sample in result.samples]
            lines.extend(f"WARN {warning}" for warning in result.warnings)
            return CommandResult(_render_summary("metrics sample", lines))
        if args.metrics_command == "show":
            samples = metrics.read_samples(args.scope, args.range_key)
            lines = [f"scope={args.scope} range={args.range_key}"]
            lines.extend(_metrics_sample_line(sample) for sample in samples)
            if not samples:
                lines.append("no samples")
            return CommandResult(_render_summary("metrics", lines))
        if args.metrics_command == "prune":
            deleted = metrics.prune()
            return CommandResult(f"metrics prune: deleted {deleted} row(s)")
    except Exception as exc:
        return CommandResult(f"metrics {args.metrics_command or 'command'} failed: {exc}", exit_code=1)
    return CommandResult("metrics command required", exit_code=2)


def _smtp_password_from_args(args: argparse.Namespace) -> tuple[str | None, CommandResult | None]:
    return _required_secret(
        getattr(args, "password_stdin", False),
        prompt="SMTP password: ",
        stdin_error="SMTP password required on stdin",
        tty_error="SMTP password prompt requires a TTY; use --password-stdin for scripts",
        empty_error="SMTP password cannot be empty",
    )


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

    result = run_wp_cli(domain, *(args.wp_args or []), interactive=True)
    return CommandResult("", exit_code=result.exit_code)


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

    if getattr(args, "command", None) != "telemetry":
        telemetry.maybe_send_async()
    result = args.handler(args)
    if result.raw_output:
        sys.stdout.write(result.message)
    else:
        print(result.message)
    return result.exit_code


def main(argv: Iterable[str] | None = None) -> int:
    return run(argv)
