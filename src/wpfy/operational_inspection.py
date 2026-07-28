from __future__ import annotations

from dataclasses import dataclass
import json, shutil, stat, subprocess
from pathlib import Path

from . import registry, traefik
from .certificate_lifecycle import cert_expiry_days, get_cert_info
from .site_definition import MYSQL_FLAVORS, SiteDefinition
from .site_layout import list_sites, site_info, web_service_lines
from .site_paths import domain_to_project, env_path, nginx_conf_path, read_env, site_dir
from .site_runtime import compose_command, docker_available, http_probe_site, nginx_config_test, runtime_skip_requested


def _current_paths():
    from .settings import PATHS as current_paths

    return current_paths


@dataclass(frozen=True, slots=True)
class InspectionCheck:
    name: str
    ok: bool | None
    message: str


@dataclass(frozen=True, slots=True)
class AggregateInfo:
    sites: tuple[dict, ...]
    traefik_message: str
    docker_version: str


@dataclass(frozen=True, slots=True)
class ServiceInfo:
    heading: str
    checks: tuple[InspectionCheck, ...]


def nginx_service_info(domain: str) -> ServiceInfo:
    project = domain_to_project(domain)
    try:
        definition = SiteDefinition.from_env(domain, read_env(env_path(domain)))
        generated = "\n".join(web_service_lines(definition)).rstrip()
    except (OSError, ValueError) as exc:
        checks = [InspectionCheck("generated service", False, f"unavailable: {exc}")]
    else:
        checks = [InspectionCheck("generated service", True, generated)]
    config_path = nginx_conf_path(domain)
    try:
        config = config_path.read_text(encoding="utf-8").rstrip()
    except FileNotFoundError:
        checks.append(InspectionCheck("mounted nginx config", False, f"not found: {config_path}"))
    except OSError as exc:
        checks.append(InspectionCheck("mounted nginx config", False, f"unavailable: {exc}"))
    else:
        checks.append(InspectionCheck("mounted nginx config", True, f"{config_path}\n{config}"))
    return ServiceInfo(f"nginx service ({project}-web)", tuple(checks))


def _service_state(domain: str, service: str) -> InspectionCheck:
    if runtime_skip_requested() or not docker_available():
        return InspectionCheck("status", None, "runtime unavailable")
    try:
        proc = compose_command(domain, "ps", "-q", service)
    except OSError as exc:
        return InspectionCheck("status", None, f"runtime unavailable: {exc}")
    if proc.returncode != 0:
        message = proc.stderr.strip() or proc.stdout.strip() or "docker compose ps failed"
        return InspectionCheck("status", None, f"runtime unavailable: {message}")
    if not proc.stdout.strip():
        return InspectionCheck("status", None, "stopped")
    return InspectionCheck("status", True, "running")


def php_service_info(domain: str) -> ServiceInfo:
    project = domain_to_project(domain)
    state = _service_state(domain, "app")
    if state.ok is not True:
        return ServiceInfo(f"php service ({project}-app)", (state,))
    try:
        proc = compose_command(domain, "exec", "-T", "app", "php", "-m")
    except OSError as exc:
        check = InspectionCheck("loaded modules", False, f"query failed: {exc}")
    else:
        if proc.returncode == 0:
            check = InspectionCheck("loaded modules", True, proc.stdout.rstrip())
        else:
            message = proc.stderr.strip() or proc.stdout.strip() or "docker compose exec failed"
            check = InspectionCheck("loaded modules", False, f"query failed: {message}")
    return ServiceInfo(f"php service ({project}-app)", (state, check))


def mysql_service_info(domain: str) -> ServiceInfo:
    project = domain_to_project(domain)
    try:
        definition = SiteDefinition.from_env(domain, read_env(env_path(domain)))
    except (OSError, ValueError) as exc:
        check = InspectionCheck("status", False, f"site definition unavailable: {exc}")
        return ServiceInfo(f"mysql service ({project}-db)", (check,))
    if not definition.use_mysql:
        check = InspectionCheck("status", None, "not applicable (site has no mysql service)")
        return ServiceInfo(f"mysql service ({project}-db)", (check,))
    state = _service_state(domain, "db")
    if state.ok is not True:
        return ServiceInfo(f"mysql service ({project}-db)", (state,))
    try:
        proc = compose_command(
            domain,
            "exec",
            "-T",
            "db",
            "mariadb",
            "-e",
            "SHOW VARIABLES WHERE Variable_name IN "
            "('version','max_connections','innodb_buffer_pool_size','datadir')",
        )
    except OSError as exc:
        check = InspectionCheck("config variables", False, f"query failed: {exc}")
    else:
        if proc.returncode == 0:
            check = InspectionCheck("config variables", True, proc.stdout.rstrip())
        else:
            message = proc.stderr.strip() or proc.stdout.strip() or "docker compose exec failed"
            check = InspectionCheck("config variables", False, f"query failed: {message}")
    return ServiceInfo(f"mysql service ({project}-db)", (state, check))


def aggregate_info() -> AggregateInfo:
    sites = tuple(list_sites())
    try:
        traefik_message = traefik.traefik_status().message
    except (FileNotFoundError, OSError, subprocess.SubprocessError) as exc:
        traefik_message = f"traefik status unavailable ({exc})"
    if not shutil.which("docker"):
        return AggregateInfo(sites, traefik_message, "unavailable")
    proc = subprocess.run(
        ["docker", "version", "--format", "{{.Server.Version}}"],
        check=False,
        capture_output=True,
        text=True,
    )
    docker_version = proc.stdout.strip() if proc.returncode == 0 and proc.stdout.strip() else "unavailable"
    return AggregateInfo(sites, traefik_message, docker_version)


def system_diagnostics() -> tuple[InspectionCheck, ...]:
    checks = []
    if not shutil.which("docker"):
        return (InspectionCheck("Docker", False, "Docker command not found"),)
    proc = subprocess.run(["docker", "info"], check=False, capture_output=True, text=True)
    docker_ok = proc.returncode == 0
    checks.append(InspectionCheck(
        "Docker",
        docker_ok,
        "Docker daemon responding" if docker_ok else f"Docker daemon unreachable ({proc.returncode})",
    ))
    if not docker_ok:
        return tuple(checks)

    running = traefik.traefik_running()
    status = traefik.traefik_status().message.strip()
    checks.append(InspectionCheck(
        "Traefik",
        running,
        f"Traefik {'running' if running else 'not running'}; {status}",
    ))

    proc = subprocess.run(
        ["docker", "system", "df", "--format", "{{.Type}}\t{{.Size}}"],
        check=False,
        capture_output=True,
        text=True,
    )
    disk_ok = proc.returncode == 0
    disk_lines = [line.strip() for line in proc.stdout.splitlines() if line.strip()]
    disk_message = (
        f"disk usage: {len(disk_lines)} entries; {proc.stdout.strip()[:200]}"
        if disk_ok else "docker system df failed"
    )
    checks.append(InspectionCheck("Disk", disk_ok, disk_message))
    checks.append(_registry_consistency())
    return tuple(checks)


def _registry_consistency() -> InspectionCheck:
    try:
        registered = {site["domain"] for site in registry.list_sites()}
    except (OSError, KeyError):
        registered = set()
    filesystem = set()
    try:
        for child in Path(_current_paths().sites_dir).iterdir():
            if child.is_dir() and (child / ".env").exists() and (child / "compose.yaml").exists():
                filesystem.add(child.name)
    except OSError:
        filesystem = set()
    missing_in_fs = registered - filesystem
    missing_in_registry = filesystem - registered
    if not missing_in_fs and not missing_in_registry:
        return InspectionCheck("Registry", True, f"registry + filesystem consistent ({len(registered)} sites)")
    messages = []
    if missing_in_fs: messages.append(f"registry has orphaned entries: {', '.join(sorted(missing_in_fs))}")
    if missing_in_registry: messages.append(f"filesystem has untracked dirs: {', '.join(sorted(missing_in_registry))}")
    return InspectionCheck("Registry", False, "; ".join(messages))


def site_diagnostics(domain: str) -> tuple[InspectionCheck, ...]:
    checks = []
    root = Path(_current_paths().sites_dir) / domain
    scaffold_ok = (root / "compose.yaml").exists()
    checks.append(InspectionCheck("scaffold", scaffold_ok, "compose.yaml exists" if scaffold_ok else "scaffold missing"))
    if not scaffold_ok: return tuple(checks)

    proc = subprocess.run(
        ["docker", "compose", "ps", "--format", "json"],
        cwd=root,
        check=False,
        capture_output=True,
        text=True,
    )
    checks.append(InspectionCheck(
        "compose ps",
        proc.returncode == 0,
        proc.stdout.strip()[:120] if proc.returncode == 0 else proc.stderr.strip()[:120] or "ps failed",
    ))
    proc = subprocess.run(
        ["docker", "compose", "-f", str(root / "compose.yaml"), "config", "--quiet"],
        check=False,
        capture_output=True,
        text=True,
    )
    checks.append(InspectionCheck(
        "compose config",
        proc.returncode == 0,
        "valid" if proc.returncode == 0 else proc.stderr.strip()[:120] or "config invalid",
    ))
    try:
        nginx_config = nginx_config_test(domain)
        checks.append(InspectionCheck(
            "nginx config",
            nginx_config.ran and nginx_config.exit_code == 0,
            nginx_config.message,
        ))
    except (OSError, subprocess.SubprocessError, ValueError) as exc:
        checks.append(InspectionCheck("nginx config", False, str(exc)))
    try:
        probe = http_probe_site(domain)
        checks.append(InspectionCheck("http probe", probe.ran and probe.exit_code == 0, probe.message))
    except (OSError, subprocess.SubprocessError, ValueError) as exc:
        checks.append(InspectionCheck("http probe", False, str(exc)))

    cert_info = get_cert_info(domain)
    if cert_info.get("status") != "issued":
        checks.append(InspectionCheck("ssl expiry", None, "no certificate found"))
    else:
        expiry = cert_expiry_days(domain)
        if expiry is None:
            checks.append(InspectionCheck("ssl expiry", None, "certificate found; expiry unavailable"))
        elif expiry < 0:
            checks.append(InspectionCheck("ssl expiry", False, f"certificate expired {abs(expiry)} days ago"))
        elif expiry < 14:
            checks.append(InspectionCheck("ssl expiry", False, f"certificate expires in {expiry} days"))
        elif expiry < 30:
            checks.append(InspectionCheck("ssl expiry", True, f"certificate expires in {expiry} days (WARN <30d)"))
        else:
            checks.append(InspectionCheck("ssl expiry", True, f"certificate expires in {expiry} days"))

    try:
        flavor = site_info(domain).get("flavor", "")
        needs_db = flavor in MYSQL_FLAVORS
    except (FileNotFoundError, ValueError, OSError):
        needs_db = False
    if not needs_db:
        checks.append(InspectionCheck("db ping", None, "not applicable (no mysql)"))
        return tuple(checks)
    proc = subprocess.run(
        ["docker", "compose", "exec", "-T", "db", "mariadb-admin", "ping", "-h", "localhost"],
        cwd=root,
        check=False,
        capture_output=True,
        text=True,
    )
    checks.append(InspectionCheck(
        "db ping",
        proc.returncode == 0,
        "mariadb responding" if proc.returncode == 0 else proc.stderr.strip()[:80] or "db ping failed",
    ))
    return tuple(checks)


def security_checks(domain: str) -> tuple[InspectionCheck, ...]:
    checks = []
    project = domain_to_project(domain)
    containers = tuple(f"{project}-{service}" for service in ("web", "app", "db", "redis", "sftp"))
    proc = subprocess.run(
        ["docker", "inspect", *containers],
        check=False,
        capture_output=True,
        text=True,
    )
    try:
        data = json.loads(proc.stdout) if proc.stdout.strip() else []
        inspected = {info.get("Name", "").lstrip("/"): info for info in data}
    except (AttributeError, json.JSONDecodeError, TypeError) as exc:
        checks.extend(InspectionCheck(container, None, f"inspect parse error: {exc}") for container in containers)
    else:
        for container in containers:
            info = inspected.get(container)
            if info is None:
                checks.append(InspectionCheck(f"container {container}", None, "not running (skip)"))
                continue
            checks.extend(_container_security_checks(container, info, info.get("HostConfig", {})))

    for path, label, expected in (
        (site_dir(domain) / ".env", ".env", 0o600),
        (site_dir(domain) / "compose.yaml", "compose.yaml", 0o644),
    ):
        if not path.exists():
            checks.append(InspectionCheck(label, None, "not found"))
            continue
        actual = stat.S_IMODE(path.stat().st_mode)
        checks.append(InspectionCheck(
            label,
            actual == expected,
            f"perms {oct(actual)}" if actual == expected else f"perms {oct(actual)} (expected {oct(expected)})",
        ))
    return tuple(checks)


def _container_security_checks(container: str, info: dict, host: dict) -> list[InspectionCheck]:
    checks = []
    privileged = bool(host.get("Privileged", False))
    checks.append(InspectionCheck(container, not privileged, "not privileged" if not privileged else "privileged mode enabled"))
    security_opt = host.get("SecurityOpt", []) or []
    checks.append(InspectionCheck(
        container,
        True if "no-new-privileges:true" in security_opt else None,
        "no-new-privileges enabled" if "no-new-privileges:true" in security_opt else "no-new-privileges not enabled",
    ))
    cap_drop = host.get("CapDrop", []) or []
    raw_dropped = "NET_RAW" in cap_drop or "ALL" in cap_drop
    checks.append(InspectionCheck(
        container,
        True if raw_dropped else None,
        "raw network capability dropped" if raw_dropped else "NET_RAW capability not dropped",
    ))
    pids = host.get("PidsLimit", 0) or 0
    checks.append(InspectionCheck(container, True if pids > 0 else None, f"pids_limit={pids}" if pids else "no PID limit configured"))
    memory = host.get("Memory", 0) or 0
    checks.append(InspectionCheck(
        container,
        True if memory > 0 else None,
        "memory limit configured" if memory else "no memory limit configured",
    ))
    log_config = host.get("LogConfig", {}) or {}
    log_options = log_config.get("Config", {}) or {}
    rotated = log_config.get("Type") == "json-file" and log_options.get("max-size") and log_options.get("max-file")
    checks.append(InspectionCheck(
        container,
        True if rotated else None,
        "log rotation configured" if rotated else "log rotation not configured",
    ))
    user = info.get("Config", {}).get("User", "")
    non_root = user not in ("root", "0", "")
    checks.append(InspectionCheck(
        container,
        True if non_root else None,
        f"user={user}" if non_root else "running as root (no explicit non-root user)",
    ))
    bindings = host.get("PortBindings", {}) or {}
    checks.append(InspectionCheck(
        container,
        None if bindings else True,
        f"host port bindings: {', '.join(bindings.keys())}" if bindings else "no host port bindings",
    ))
    return checks
