from __future__ import annotations

from dataclasses import dataclass, replace
import socket
import subprocess

from .events import record_event
from .site_definition import PHP_SETTING_FIELDS, SiteDefinition, validate_php_setting
from .site_layout import ensure_site_scaffold, validate_php_custom
from .site_paths import env_path, read_env, site_exists, validate_domain
from .site_runtime import RuntimeResult, compose_command, docker_available, runtime_skip_requested


_DEFAULT_ADMINER_PORT = 8081


@dataclass(frozen=True, slots=True)
class ConfigurationResult:
    exit_code: int
    message: str
    changes: tuple[str, ...] = ()
    touched: tuple[str, ...] = ()
    runtime: RuntimeResult = RuntimeResult(0, "no runtime change", skipped=True)


def _definition(domain: str) -> SiteDefinition:
    validate_domain(domain)
    if not site_exists(domain):
        raise FileNotFoundError(f"site not found: {domain}")
    return SiteDefinition.from_env(domain, read_env(env_path(domain)))


def php_settings(domain: str) -> dict[str, str]:
    definition = _definition(domain)
    return {name: getattr(definition, name) for name in PHP_SETTING_FIELDS}


def _restart_php_services(domain: str) -> RuntimeResult:
    if runtime_skip_requested() or not docker_available():
        return RuntimeResult(0, "runtime restart skipped", skipped=True)
    try:
        validation = validate_php_custom(domain)
        if validation.exit_code == 1:
            return RuntimeResult(1, f"PHP restart refused: {validation.message}")
        proc = compose_command(domain, "up", "-d", "--force-recreate", "app", "web")
    except (OSError, subprocess.SubprocessError) as exc:
        return RuntimeResult(3, f"runtime restart failed: {exc}")
    message = proc.stderr.strip() or proc.stdout.strip() or "PHP and web services restarted"
    return RuntimeResult(proc.returncode, message, ran=proc.returncode == 0)


def update_php_settings(
    domain: str,
    *,
    php_memory_limit: str | None = None,
    php_max_execution_time: str | None = None,
    php_max_input_time: str | None = None,
    php_max_input_vars: str | None = None,
    php_upload_max_size: str | None = None,
    reset: bool = False,
    dry_run: bool = False,
) -> ConfigurationResult:
    definition = _definition(domain)
    requested = {
        "php_memory_limit": php_memory_limit,
        "php_max_execution_time": php_max_execution_time,
        "php_max_input_time": php_max_input_time,
        "php_max_input_vars": php_max_input_vars,
        "php_upload_max_size": php_upload_max_size,
    }
    if reset:
        requested = {name: metadata[1] for name, metadata in PHP_SETTING_FIELDS.items()}
    else:
        for name, value in requested.items():
            if value is not None:
                validate_php_setting(name, value)

    updates = {
        name: value
        for name, value in requested.items()
        if value is not None and value != getattr(definition, name)
    }
    changes = tuple(f"{name} {getattr(definition, name)}→{value}" for name, value in updates.items())
    if dry_run:
        return ConfigurationResult(0, "dry run", changes=changes)
    if not updates:
        try:
            touched = tuple(ensure_site_scaffold(definition))
        except ValueError as exc:
            return ConfigurationResult(2, str(exc))
        runtime = _restart_php_services(domain)
        return ConfigurationResult(
            runtime.exit_code,
            "PHP settings already up to date" if runtime.exit_code == 0 else runtime.message,
            touched=touched,
            runtime=runtime,
        )

    desired = replace(definition, **updates)
    try:
        touched = tuple(ensure_site_scaffold(desired))
    except ValueError as exc:
        return ConfigurationResult(2, str(exc), changes=changes)

    runtime = _restart_php_services(domain)
    exit_code = runtime.exit_code
    record_event(
        "site.php-settings",
        domain=domain,
        outcome="ok" if exit_code == 0 else "failed",
        detail="per-site PHP settings updated",
    )
    return ConfigurationResult(
        exit_code,
        "PHP settings updated" if exit_code == 0 else runtime.message,
        changes=changes,
        touched=touched,
        runtime=runtime,
    )


def _port_available(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(0.2)
        return sock.connect_ex(("127.0.0.1", port)) != 0


def _used_ports(domain: str) -> set[int]:
    used: set[int] = set()
    sites_root = env_path(domain).parent.parent
    if not sites_root.exists():
        return used
    for candidate in sites_root.glob("*/.env"):
        if candidate == env_path(domain):
            continue
        values = read_env(candidate)
        for key in ("ADMINER_PORT", "SFTP_PORT"):
            value = values.get(key)
            if value and value.isdigit():
                used.add(int(value))
    return used


def _adminer_port(domain: str, requested: int | str | None, current: str | None) -> str:
    if requested is not None:
        try:
            port = int(requested)
        except (TypeError, ValueError) as exc:
            raise ValueError("Adminer port must be an integer") from exc
        if port < 1 or port > 65535:
            raise ValueError("Adminer port must be between 1 and 65535")
        if port in _used_ports(domain):
            raise ValueError(f"Adminer port is already assigned: {port}")
        return str(port)
    if current:
        return current
    used = _used_ports(domain)
    port = _DEFAULT_ADMINER_PORT
    while port in used or not _port_available(port):
        port += 1
        if port > 65535:
            raise ValueError("no loopback port is available for Adminer")
    return str(port)


def configure_adminer(
    domain: str,
    *,
    enabled: bool,
    port: int | str | None = None,
    dry_run: bool = False,
) -> ConfigurationResult:
    definition = _definition(domain)
    if not definition.use_mysql:
        return ConfigurationResult(2, f"site has no database service: {domain}")
    desired_port = _adminer_port(domain, port, definition.adminer_port) if enabled else None
    if not enabled and definition.adminer_port is None:
        return ConfigurationResult(0, "Adminer already disabled")
    changes = () if desired_port == definition.adminer_port else (
        f"Adminer {'enabled on 127.0.0.1:' + desired_port if enabled else 'disabled'}",
    )
    if dry_run:
        return ConfigurationResult(0, "dry run", changes=changes)

    if not enabled and not runtime_skip_requested() and docker_available():
        proc = compose_command(domain, "rm", "-sf", "adminer")
        if proc.returncode != 0:
            message = proc.stderr.strip() or proc.stdout.strip() or "failed to remove Adminer container"
            return ConfigurationResult(proc.returncode or 1, message, changes=changes)

    try:
        touched = tuple(ensure_site_scaffold(replace(definition, adminer_port=desired_port)))
    except ValueError as exc:
        return ConfigurationResult(2, str(exc), changes=changes)

    if runtime_skip_requested() or not docker_available():
        runtime = RuntimeResult(0, "runtime change skipped", skipped=True)
    elif enabled:
        proc = compose_command(domain, "up", "-d", "adminer")
        message = proc.stderr.strip() or proc.stdout.strip() or "Adminer started"
        runtime = RuntimeResult(proc.returncode, message, ran=proc.returncode == 0)
    else:
        runtime = RuntimeResult(0, "Adminer container removed", ran=True)
    record_event(
        "site.adminer",
        domain=domain,
        outcome="ok" if runtime.exit_code == 0 else "failed",
        detail=f"Adminer {'enabled' if enabled else 'disabled'}",
    )
    return ConfigurationResult(
        runtime.exit_code,
        f"Adminer {'enabled' if enabled else 'disabled'} for {domain}",
        changes=changes,
        touched=touched,
        runtime=runtime,
    )
