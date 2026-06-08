from __future__ import annotations

import argparse
import getpass
import importlib.metadata
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable
from urllib.error import URLError
from urllib.request import Request, urlopen

from . import __version__
from . import registry
from . import sftp
from . import site_lifecycle
from . import traefik
from . import operational_inspection
from .php_runtime import DEFAULT_PHP_VERSION, PHP_IMAGE_REPOSITORY, SUPPORTED_PHP_VERSIONS, php_image
from .certificate_lifecycle import cert_expiry_days, force_renew_cert, get_cert_info, preflight_ssl
from .site_layout import (
    WORDPRESS_FLAVORS,
    backup_site,
    compose_command,
    compose_path,
    domain_to_project,
    env_path,
    generated_secret,
    list_sites,
    nginx_conf_path,
    read_env,
    remove_site_scaffold,
    restore_site,
    site_health,
    site_info,
    site_exists,
    site_dir,
    stop_site_runtime,
)


class WpfyHelpFormatter(argparse.ArgumentDefaultsHelpFormatter, argparse.RawDescriptionHelpFormatter):
    pass


@dataclass(frozen=True)
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


def _enabled_text(value: object) -> str:
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
            "  wpfy site create example.com --wp\n"
            "  wpfy site create example.com --wp -le\n"
            "  wpfy stack install --nginx --php --mysql\n"
            "  wpfy site status example.com\n"
        ),
        formatter_class=WpfyHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"wpfy {__version__}")
    subparsers = parser.add_subparsers(dest="command")

    add_site_parser(subparsers)
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


def add_simple_command(subparsers: argparse._SubParsersAction[argparse.ArgumentParser], name: str) -> None:
    parser = subparsers.add_parser(name)
    parser.set_defaults(handler=lambda args: CommandResult(f"{name} command scaffolded"))


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


def add_site_parser(subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    parser = _add_parser(
        subparsers,
        "site",
        help="Create, inspect, update, and remove managed sites.",
        description="Manage per-site scaffolds, runtime state, SSL, backups, and restore flows.",
        epilog=(
            "Examples:\n"
            "  wpfy site create example.com --wp\n"
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
    create.add_argument("domain")
    create.add_argument("--html", action="store_true")
    create.add_argument("--php", choices=SUPPORTED_PHP_VERSIONS, default=DEFAULT_PHP_VERSION)
    create.add_argument("--mysql", action="store_true")
    create.add_argument("--wp", action="store_true")
    create.add_argument("--wpfc", action="store_true")
    create.add_argument("--wpredis", action="store_true")
    create.add_argument("--wpsc", action="store_true")
    create.add_argument("--wprocket", action="store_true")
    create.add_argument("--wpce", action="store_true")
    create.add_argument("--wpsubdir", action="store_true")
    create.add_argument("--wpsubdomain", action="store_true")
    create.add_argument("-le", "--letsencrypt", nargs="?", const="default")
    create.add_argument("--dns")
    create.add_argument(
        "--proxied",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="force proxied (HTTP-01) mode on/off; default auto-detects Cloudflare",
    )
    create.add_argument("--user", dest="wp_user", help="WordPress administrator username")
    create.add_argument("--email", dest="wp_email", help="WordPress administrator email")
    create.add_argument("--pass", dest="wp_password", help="WordPress administrator password")
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
    backup.set_defaults(handler=handle_site_backup)

    restore = _add_parser(
        site_subparsers,
        "restore",
        help="Restore a site from a backup archive.",
    )
    restore.add_argument("domain")
    restore.add_argument("backup")
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
    update.set_defaults(handler=handle_site_update)


def add_stack_parser(subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    parser = _add_parser(
        subparsers,
        "stack",
        help="Install or inspect shared runtime components.",
        description="Pull and inspect Traefik, PHP, MariaDB, Redis, and wp-cli images.",
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
                stop_result = stop_site_runtime(domain)
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
        image = "mariadb:11.4"
        _progress("Pulling MariaDB 11.4 image...")
        proc = subprocess.run(["docker", "pull", image], check=False, capture_output=True, text=True)
        if proc.returncode == 0:
            results.append(f"MariaDB: OK pulled {image}")
        else:
            err = proc.stderr.strip() or proc.stdout.strip() or "pull failed"
            results.append(f"MariaDB: FAIL {err}")
            exit_code = proc.returncode or 1

    if install_all or getattr(args, "redis", False):
        image = "redis:7-alpine"
        _progress("Pulling Redis 7 image...")
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

    deferred_flags = ["phpmyadmin", "adminer", "composer", "mysqltuner"]
    for flag in deferred_flags:
        if getattr(args, flag, False):
            results.append(f"{flag}: WARN not yet implemented, deferred to v2")

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
        f"mariadb:11.4 redis:7-alpine {traefik.TRAEFIK_IMAGE}"
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
        proxied_override=getattr(args, "proxied", None),
        password=args.password,
    )
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
        _section("site updated"),
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


def handle_site_ssl(args: argparse.Namespace) -> CommandResult:
    domain = args.domain
    preflight_only = getattr(args, "preflight_only", False)
    renew = getattr(args, "renew", False)
    status_flag = getattr(args, "status", False)
    letsencrypt = getattr(args, "letsencrypt", None)

    if letsencrypt == "wildcard":
        return CommandResult(_render_summary("ssl", ["wildcard SSL is not yet supported; no certificate was requested"]), exit_code=2)

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
    result = backup_site(args.domain)
    return CommandResult(_render_summary("site backup", [_step_line("backup", result)]), exit_code=result.exit_code)


def handle_site_restore(args: argparse.Namespace) -> CommandResult:
    result = restore_site(args.domain, args.backup)
    return CommandResult(_render_summary("site restore", [_step_line("restore", result)]), exit_code=result.exit_code)


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


def run(argv: Iterable[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)

    if not hasattr(args, "handler"):
        parser.print_help()
        return 0

    result = args.handler(args)
    print(result.message)
    return result.exit_code


def main(argv: Iterable[str] | None = None) -> int:
    return run(argv)
