from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from .php_runtime import DEFAULT_PHP_VERSION
from .site_layout import (
    RuntimeResult,
    SiteSpec,
    apply_site_ownership,
    bootstrap_site_files,
    compose_command,
    ensure_site_scaffold,
    env_path,
    provision_wordpress_site,
    read_env,
    site_info,
    start_site_runtime,
    wordpress_install_state,
    wp_cli_command,
)
from .certificate_lifecycle import preflight_ssl
from .dns import DNSConfigError, load_cloudflare_config
from .site_definition import MYSQL_FLAVORS, WORDPRESS_FLAVORS
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
    php_version: str = DEFAULT_PHP_VERSION
    letsencrypt: str | None = None
    dns_provider: str | None = None
    proxied_override: bool | None = None


@dataclass(frozen=True)
class UpdateSiteRequest:
    domain: str
    php_version: str | None = None
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
    php_version: str,
    letsencrypt: str | None,
    dns_provider: str | None,
    proxied: bool,
    sftp_password: str | None = None,
    sftp_port: str | None = None,
) -> SiteSpec:
    return SiteSpec(
        domain=domain,
        flavor=flavor,
        use_mysql=flavor in MYSQL_FLAVORS,
        use_redis=flavor == "wpredis",
        letsencrypt=letsencrypt,
        dns_provider=dns_provider,
        php_version=php_version,
        ssl_enabled=bool(letsencrypt),
        proxied=proxied and bool(letsencrypt),
        sftp_password=sftp_password,
        sftp_port=sftp_port,
    )


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
    # Re-own files written during bootstrap (e.g. downloaded WordPress core) with
    # the per-site uid before containers start.
    apply_site_ownership(request.domain)
    report("runtime")
    runtime = start_site_runtime(request.domain)

    wordpress_message: str | None = None
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

    return CreateSiteResult(
        spec=spec,
        touched=touched,
        bootstrap=bootstrap,
        runtime=runtime,
        preflight_message=preflight_message,
        wordpress_message=wordpress_message,
        wordpress_admin_user=wordpress_admin_user,
        generated_password=generated_password,
        exit_code=exit_code,
    )


def update_site(request: UpdateSiteRequest) -> UpdateSiteResult:
    domain = request.domain
    try:
        site_info(domain)
    except (FileNotFoundError, ValueError) as exc:
        raise SiteLifecycleError(str(exc)) from exc

    existing_env = read_env(env_path(domain))
    current_flavor = existing_env.get("SITE_FLAVOR", "unknown")
    current_php = existing_env.get("PHP_VERSION", DEFAULT_PHP_VERSION)
    current_letsencrypt = existing_env.get("LETSENCRYPT_MODE", "") or None
    current_dns = existing_env.get("DNS_PROVIDER", "") or None
    new_dns = request.dns_provider or current_dns
    current_proxied = existing_env.get("PROXIED", "") == "1"

    new_flavor = current_flavor
    if request.wpfc:
        new_flavor = "wpfc"
    if request.wpredis:
        new_flavor = "wpredis"
    if request.wpsubdir or request.wpsubdomain:
        if new_flavor not in {"wpfc", "wpredis", "wpsc", "wprocket", "wpce"}:
            new_flavor = "wp"

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
        php_version=new_php,
        letsencrypt=new_letsencrypt,
        dns_provider=new_dns,
        proxied=new_proxied,
        sftp_password=existing_env.get("SFTP_PASSWORD") or None,
        sftp_port=existing_env.get("SFTP_PORT") or None,
    )
    try:
        touched = tuple(ensure_site_scaffold(spec))
    except ValueError as exc:
        raise SiteLifecycleError(str(exc)) from exc
    runtime = start_site_runtime(domain)

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
            password_summary = f"FAIL {message.replace(request.password, '***REDACTED***')}"
        else:
            password_summary = f"OK password updated for {admin_user}"

    exit_code = runtime.exit_code if runtime.exit_code and not runtime.skipped else 0
    return UpdateSiteResult(
        spec=spec,
        touched=touched,
        runtime=runtime,
        changes=tuple(changes),
        preflight_message=preflight_message,
        password_summary=password_summary,
        exit_code=exit_code,
    )


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
    except (FileNotFoundError, ValueError) as exc:
        raise SiteLifecycleError(str(exc)) from exc

    existing_env = read_env(env_path(domain))
    flavor = existing_info.get("flavor", "site")
    spec = _site_spec(
        domain=domain,
        flavor=flavor,
        php_version=existing_env.get("PHP_VERSION", DEFAULT_PHP_VERSION),
        letsencrypt=letsencrypt,
        dns_provider=dns_provider,
        proxied=_resolve_proxied(proxied_override, preflight.mode),
        sftp_password=existing_env.get("SFTP_PASSWORD") or None,
        sftp_port=existing_env.get("SFTP_PORT") or None,
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
