from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, replace

from . import site_cache
from .php_runtime import DEFAULT_PHP_VERSION
from .redaction import redact_values
from .site_layout import (
    SiteSpec,
    apply_site_ownership,
    backup_site,
    bootstrap_site_files,
    ensure_site_scaffold,
    provision_wordpress_site,
    remove_site_scaffold,
    site_info,
    wordpress_install_state,
)
from .site_paths import env_path, read_env
from .site_runtime import RuntimeResult, compose_command, start_site_runtime, stop_site_runtime, wp_cli_command
from .events import record_event
from .certificate_lifecycle import preflight_ssl
from .dns import DNSConfigError, load_cloudflare_config
from .site_definition import LEGACY_CACHE_FLAVORS, MYSQL_FLAVORS, WORDPRESS_FLAVORS
from .traefik import acme_email_problem


@dataclass(frozen=True)
class WordPressCredentials:
    user: str
    email: str
    password: str
    password_generated: bool = False


@dataclass(frozen=True)
class CreateSiteRequest:
    domain: str
    flavor: str
    page_cache: str = "none"
    object_cache: str = "none"
    php_version: str = DEFAULT_PHP_VERSION
    letsencrypt: str | None = None
    dns_provider: str | None = None
    proxied_override: bool | None = None


@dataclass(frozen=True)
class UpdateSiteRequest:
    domain: str
    php_version: str | None = None
    flavor: str | None = None
    page_cache: str | None = None
    object_cache: str | None = None
    dry_run: bool = False
    wpfc: bool = False
    wpredis: bool = False
    wpsubdir: bool = False
    wpsubdomain: bool = False
    letsencrypt: str | None = None
    dns_provider: str | None = None
    proxied_override: bool | None = None
    password: str | None = None


@dataclass(frozen=True)
class CreateSiteResult:
    spec: SiteSpec
    touched: tuple[str, ...]
    bootstrap: RuntimeResult
    runtime: RuntimeResult
    preflight_message: str | None = None
    wordpress_message: str | None = None
    cache_message: str | None = None
    wordpress_admin_user: str | None = None
    generated_password: str | None = None
    exit_code: int = 0

    @property
    def created(self) -> bool:
        return bool(self.touched)


@dataclass(frozen=True)
class UpdateSiteResult:
    spec: SiteSpec
    touched: tuple[str, ...]
    runtime: RuntimeResult
    changes: tuple[str, ...]
    preflight_message: str | None = None
    cache_message: str | None = None
    password_summary: str | None = None
    exit_code: int = 0


@dataclass(frozen=True)
class EnableSSLResult:
    spec: SiteSpec
    touched: tuple[str, ...]
    runtime: RuntimeResult
    preflight_message: str
    wordpress_message: str | None = None
    exit_code: int = 0


@dataclass(frozen=True)
class DeleteSiteRequest:
    domain: str
    force: bool = False
    skip_backup: bool = False


@dataclass(frozen=True)
class DeleteSiteResult:
    backup: RuntimeResult
    runtime: RuntimeResult
    removed: bool
    exit_code: int = 0


class SiteLifecycleError(Exception):
    def __init__(self, message: str, *, exit_code: int = 2, preflight: bool = False) -> None:
        super().__init__(message)
        self.exit_code = exit_code
        self.preflight = preflight


def _require_acme_email() -> None:
    problem = acme_email_problem()
    if problem:
        raise SiteLifecycleError(problem, preflight=True)


def _require_wildcard_dns(letsencrypt: str | None, dns_provider: str | None) -> None:
    if letsencrypt != "wildcard":
        return
    if dns_provider != "cloudflare":
        raise SiteLifecycleError("wildcard SSL requires --dns cloudflare", preflight=True)
    try:
        load_cloudflare_config()
    except DNSConfigError as exc:
        raise SiteLifecycleError(str(exc), preflight=True) from exc


def _resolve_admin_user(domain: str) -> str:
    proc = wp_cli_command(domain, "user", "list", "--role=administrator", "--field=user_login", "--allow-root")
    if proc.returncode == 0:
        for line in proc.stdout.splitlines():
            candidate = line.strip()
            if candidate:
                return candidate
    return "admin"


def _resolve_proxied(override: bool | None, detected_mode: str | None) -> bool:
    if override is not None:
        return override
    return detected_mode == "proxied"


def _site_spec(
    *,
    domain: str,
    flavor: str,
    page_cache: str,
    object_cache: str,
    php_version: str,
    letsencrypt: str | None,
    dns_provider: str | None,
    proxied: bool,
    current: SiteSpec | None = None,
) -> SiteSpec:
    legacy_page_cache, legacy_object_cache = LEGACY_CACHE_FLAVORS.get(flavor, ("none", "none"))
    if flavor in LEGACY_CACHE_FLAVORS:
        page_cache = page_cache if page_cache != "none" else legacy_page_cache
        object_cache = object_cache if object_cache != "none" else legacy_object_cache
        flavor = "wp"
    values = {
        "domain": domain,
        "flavor": flavor,
        "use_mysql": flavor in MYSQL_FLAVORS,
        "use_redis": object_cache == "redis",
        "page_cache": page_cache,
        "object_cache": object_cache,
        "letsencrypt": letsencrypt,
        "dns_provider": dns_provider,
        "php_version": php_version,
        "ssl_enabled": bool(letsencrypt),
        "proxied": proxied and bool(letsencrypt),
    }
    if current is not None:
        if not values["use_mysql"]:
            values["adminer_port"] = None
        return replace(current, **values)
    return SiteSpec(**values)


def create_site(
    request: CreateSiteRequest,
    *,
    credentials: Callable[[], WordPressCredentials],
    progress: Callable[[str], None] | None = None,
) -> CreateSiteResult:
    report = progress or (lambda message: None)
    proxied = False
    preflight_message: str | None = None

    if request.letsencrypt:
        report("preflight")
        _require_acme_email()
        preflight = preflight_ssl(request.domain)
        if not preflight.passed:
            raise SiteLifecycleError(preflight.message, preflight=True)
        proxied = _resolve_proxied(request.proxied_override, preflight.mode)
        preflight_message = preflight.message
        _require_wildcard_dns(request.letsencrypt, request.dns_provider)

    spec = _site_spec(
        domain=request.domain,
        flavor=request.flavor,
        page_cache=request.page_cache,
        object_cache=request.object_cache,
        php_version=request.php_version,
        letsencrypt=request.letsencrypt,
        dns_provider=request.dns_provider,
        proxied=proxied,
    )

    report("scaffold")
    try:
        touched = tuple(ensure_site_scaffold(spec))
    except ValueError as exc:
        raise SiteLifecycleError(str(exc)) from exc

    report("bootstrap")
    bootstrap = bootstrap_site_files(request.domain)
    if bootstrap.exit_code != 0:
        return CreateSiteResult(
            spec=spec,
            touched=touched,
            bootstrap=bootstrap,
            runtime=RuntimeResult(
                bootstrap.exit_code,
                "runtime skipped because bootstrap failed",
                skipped=True,
            ),
            preflight_message=preflight_message,
            exit_code=bootstrap.exit_code,
        )
    # Re-own files written during bootstrap (e.g. downloaded WordPress core) with
    # the per-site uid before containers start.
    ownership = apply_site_ownership(request.domain)
    if ownership.exit_code != 0:
        return CreateSiteResult(
            spec=spec,
            touched=touched,
            bootstrap=bootstrap,
            runtime=RuntimeResult(
                ownership.exit_code,
                f"runtime skipped because ownership failed: {ownership.message}",
                skipped=True,
            ),
            preflight_message=preflight_message,
            exit_code=ownership.exit_code,
        )
    report("runtime")
    runtime = start_site_runtime(request.domain)

    wordpress_message: str | None = None
    cache_message: str | None = None
    wordpress_admin_user: str | None = None
    generated_password: str | None = None
    exit_code = runtime.exit_code or 0

    if request.flavor in WORDPRESS_FLAVORS and runtime.ran:
        report("wordpress-state")
        install_state = wordpress_install_state(request.domain)
        if install_state.exit_code == 0 and install_state.ran:
            wordpress_message = install_state.message
        elif install_state.skipped:
            wordpress_message = install_state.message
        else:
            admin = credentials()
            wordpress_admin_user = admin.user
            report("wordpress-provision")
            provision = provision_wordpress_site(
                request.domain,
                admin.user,
                admin.email,
                admin.password,
            )
            wordpress_message = provision.message
            exit_code = provision.exit_code
            if provision.exit_code == 0 and provision.ran and admin.password_generated:
                generated_password = admin.password

    if request.page_cache != "none" or request.object_cache != "none":
        if runtime.ran and exit_code == 0:
            cache_result = site_cache.configure_site_cache(request.domain)
            cache_message = cache_result.message
            exit_code = cache_result.exit_code
        else:
            cache_stage = site_cache.render_cache_nginx(request.domain)
            cache_message = cache_stage.message + "; plugin activation deferred until runtime is available"
            exit_code = exit_code or cache_stage.exit_code

    result = CreateSiteResult(
        spec=spec,
        touched=touched,
        bootstrap=bootstrap,
        runtime=runtime,
        preflight_message=preflight_message,
        wordpress_message=wordpress_message,
        cache_message=cache_message,
        wordpress_admin_user=wordpress_admin_user,
        generated_password=generated_password,
        exit_code=exit_code,
    )
    record_event(
        "site.create",
        domain=request.domain,
        outcome="ok" if exit_code == 0 else "failed",
        detail="site lifecycle completed",
    )
    return result


def update_site(request: UpdateSiteRequest) -> UpdateSiteResult:
    domain = request.domain
    try:
        site_info(domain)
    except OSError as exc:
        raise SiteLifecycleError(f"unsafe site environment: {exc}") from exc
    except (FileNotFoundError, ValueError) as exc:
        raise SiteLifecycleError(str(exc)) from exc

    try:
        existing_env = read_env(env_path(domain))
    except OSError as exc:
        raise SiteLifecycleError(f"unsafe site environment: {exc}") from exc
    current_spec = SiteSpec.from_env(domain, existing_env)
    current_flavor = current_spec.flavor
    current_page_cache = current_spec.page_cache
    current_object_cache = current_spec.object_cache
    current_php = current_spec.php_version
    current_letsencrypt = current_spec.letsencrypt
    current_dns = current_spec.dns_provider
    new_dns = request.dns_provider or current_dns
    current_proxied = current_spec.proxied

    new_flavor = request.flavor or current_flavor
    if request.wpsubdir:
        new_flavor = "wpsubdir"
    elif request.wpsubdomain:
        new_flavor = "wpsubdomain"
    new_page_cache = request.page_cache or current_page_cache
    new_object_cache = request.object_cache or current_object_cache
    if request.wpfc:
        new_page_cache = "wpfc"
    if request.wpredis:
        new_object_cache = "redis"

    new_php = request.php_version or current_php
    if request.letsencrypt is None:
        new_letsencrypt = current_letsencrypt
    elif request.letsencrypt == "off":
        new_letsencrypt = None
    else:
        new_letsencrypt = request.letsencrypt

    changes: list[str] = []
    if new_php != current_php:
        changes.append(f"php {current_php}→{new_php}")
    if new_flavor != current_flavor:
        changes.append(f"flavor {current_flavor}→{new_flavor}")
    if new_page_cache != current_page_cache:
        changes.append(f"page cache {current_page_cache}→{new_page_cache}")
    if new_object_cache != current_object_cache:
        changes.append(f"object cache {current_object_cache}→{new_object_cache}")
    if (new_letsencrypt or "") != (current_letsencrypt or ""):
        changes.append(f"ssl enabled ({new_letsencrypt})" if new_letsencrypt else "ssl disabled")
    if (new_dns or "") != (current_dns or ""):
        changes.append(f"dns provider {current_dns or 'none'}→{new_dns}")

    preflight_message: str | None = None
    detected_mode: str | None = None
    if new_letsencrypt and not current_letsencrypt:
        _require_acme_email()
        preflight = preflight_ssl(domain)
        if not preflight.passed:
            raise SiteLifecycleError(preflight.message, preflight=True)
        preflight_message = preflight.message
        detected_mode = preflight.mode
    _require_wildcard_dns(new_letsencrypt, new_dns)

    if request.proxied_override is not None:
        new_proxied = request.proxied_override
    elif detected_mode is not None:
        new_proxied = detected_mode == "proxied"
    else:
        new_proxied = current_proxied

    spec = _site_spec(
        domain=domain,
        flavor=new_flavor,
        page_cache=new_page_cache,
        object_cache=new_object_cache,
        php_version=new_php,
        letsencrypt=new_letsencrypt,
        dns_provider=new_dns,
        proxied=new_proxied,
        current=current_spec,
    )
    if request.dry_run:
        return UpdateSiteResult(
            spec=spec,
            touched=(),
            runtime=RuntimeResult(0, "dry run", skipped=True),
            changes=tuple(changes),
        )

    try:
        touched = tuple(ensure_site_scaffold(spec))
    except ValueError as exc:
        raise SiteLifecycleError(str(exc)) from exc
    runtime = start_site_runtime(domain)

    cache_message: str | None = None
    cache_exit_code = 0
    cache_changed = new_page_cache != current_page_cache or new_object_cache != current_object_cache
    if cache_changed:
        if runtime.ran and runtime.exit_code == 0:
            cache_result = site_cache.configure_site_cache(domain)
            cache_message = cache_result.message
            cache_exit_code = cache_result.exit_code
        else:
            cache_stage = site_cache.render_cache_nginx(domain)
            cache_message = cache_stage.message + "; plugin activation deferred until runtime is available"
            cache_exit_code = cache_stage.exit_code

    password_summary: str | None = None
    if request.password:
        admin_user = _resolve_admin_user(domain)
        # The password travels over stdin (--prompt) so it never appears in
        # process argv on the host or inside the container.
        proc = wp_cli_command(
            domain,
            "user",
            "update",
            admin_user,
            "--skip-email",
            "--prompt=user_pass",
            "--allow-root",
            input_text=request.password + "\n",
        )
        if proc.returncode != 0:
            message = proc.stderr.strip() or proc.stdout.strip() or "wp user update failed"
            password_summary = f"FAIL {redact_values(message, (request.password,))}"
        else:
            password_summary = f"OK password updated for {admin_user}"

    exit_code = runtime.exit_code if runtime.exit_code and not runtime.skipped else cache_exit_code
    if password_summary and password_summary.startswith("FAIL "):
        exit_code = exit_code or 1
    result = UpdateSiteResult(
        spec=spec,
        touched=touched,
        runtime=runtime,
        changes=tuple(changes),
        preflight_message=preflight_message,
        cache_message=cache_message,
        password_summary=password_summary,
        exit_code=exit_code,
    )
    record_event(
        "site.config",
        domain=domain,
        outcome="ok" if exit_code == 0 else "failed",
        detail="site configuration updated",
    )
    return result


def enable_ssl(
    domain: str,
    *,
    letsencrypt: str,
    dns_provider: str | None = None,
    proxied_override: bool | None = None,
) -> EnableSSLResult:
    _require_acme_email()
    preflight = preflight_ssl(domain)
    if not preflight.passed:
        raise SiteLifecycleError(preflight.message, preflight=True)
    _require_wildcard_dns(letsencrypt, dns_provider)

    try:
        existing_info = site_info(domain)
    except OSError as exc:
        raise SiteLifecycleError(f"unsafe site environment: {exc}") from exc
    except (FileNotFoundError, ValueError) as exc:
        raise SiteLifecycleError(str(exc)) from exc

    try:
        existing_env = read_env(env_path(domain))
    except OSError as exc:
        raise SiteLifecycleError(f"unsafe site environment: {exc}") from exc
    current_spec = SiteSpec.from_env(domain, existing_env)
    flavor = current_spec.flavor
    spec = _site_spec(
        domain=domain,
        flavor=flavor,
        page_cache=current_spec.page_cache,
        object_cache=current_spec.object_cache,
        php_version=current_spec.php_version,
        letsencrypt=letsencrypt,
        dns_provider=dns_provider,
        proxied=_resolve_proxied(proxied_override, preflight.mode),
        current=current_spec,
    )
    try:
        touched = tuple(ensure_site_scaffold(spec))
    except ValueError as exc:
        raise SiteLifecycleError(str(exc)) from exc
    runtime = start_site_runtime(domain)
    wordpress_message: str | None = None
    exit_code = runtime.exit_code or 0
    if flavor in WORDPRESS_FLAVORS and runtime.ran and runtime.exit_code == 0:
        site_url = f"https://{domain}"
        for option in ("home", "siteurl"):
            proc = compose_command(
                domain,
                "--profile",
                "cli",
                "run",
                "--rm",
                "wpcli",
                "option",
                "update",
                option,
                site_url,
                "--allow-root",
            )
            if proc.returncode != 0:
                message = proc.stderr.strip() or proc.stdout.strip() or f"failed to update WordPress {option}"
                wordpress_message = f"FAIL {message}"
                exit_code = proc.returncode or 1
                break
        else:
            wordpress_message = f"OK home and siteurl updated to {site_url}"

    return EnableSSLResult(
        spec=spec,
        touched=touched,
        runtime=runtime,
        preflight_message=preflight.message,
        wordpress_message=wordpress_message,
        exit_code=exit_code,
    )


def delete_site(request: DeleteSiteRequest) -> DeleteSiteResult:
    domain = request.domain
    try:
        site_info(domain)
    except FileNotFoundError as exc:
        raise SiteLifecycleError(str(exc)) from exc
    except OSError as exc:
        raise SiteLifecycleError(f"unsafe site environment: {exc}") from exc
    except ValueError as exc:
        raise SiteLifecycleError(str(exc)) from exc

    if request.skip_backup:
        backup = RuntimeResult(0, "backup skipped by request", skipped=True)
    else:
        backup = backup_site(domain, require_database=True)
        if backup.exit_code != 0 or backup.skipped:
            record_event("site.delete", domain=domain, outcome="failed", detail="backup failed")
            blocked = RuntimeResult(0, "runtime blocked by backup failure", skipped=True)
            return DeleteSiteResult(backup, blocked, False, backup.exit_code or 1)

    runtime = stop_site_runtime(domain, remove_volumes=True)
    if runtime.exit_code != 0 or runtime.skipped:
        record_event("site.delete", domain=domain, outcome="failed", detail="runtime stop failed")
        return DeleteSiteResult(backup, runtime, False, runtime.exit_code or 1)

    removed = remove_site_scaffold(domain)
    exit_code = 0 if removed else 2
    record_event(
        "site.delete",
        domain=domain,
        outcome="ok" if removed else "failed",
        detail="site scaffold removed" if removed else "site scaffold not found",
    )
    return DeleteSiteResult(backup, runtime, removed, exit_code)
