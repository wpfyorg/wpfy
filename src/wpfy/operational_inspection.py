from __future__ import annotations

from dataclasses import dataclass
import json, shutil, stat, subprocess
from pathlib import Path

from . import registry, traefik
from .certificate_lifecycle import cert_expiry_days, get_cert_info
from .settings import PATHS
from .site_definition import MYSQL_FLAVORS
from .site_layout import (
    _http_probe_site,
    domain_to_project,
    list_sites,
    site_dir,
    site_info,
)


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
        for child in Path(PATHS.sites_dir).iterdir():
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
    root = Path(PATHS.sites_dir) / domain
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
        probe = _http_probe_site(domain)
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
    for service in ("web", "app", "db", "redis", "sftp"):
        container = f"{project}-{service}"
        proc = subprocess.run(
            ["docker", "inspect", container],
            check=False,
            capture_output=True,
            text=True,
        )
        if proc.returncode != 0:
            checks.append(InspectionCheck(f"container {container}", None, "not running (skip)"))
            continue
        try:
            data = json.loads(proc.stdout)
            info = data[0]
            host = info.get("HostConfig", {})
        except (json.JSONDecodeError, IndexError, KeyError) as exc:
            checks.append(InspectionCheck(container, None, f"inspect parse error: {exc}"))
            continue
        checks.extend(_container_security_checks(container, info, host))

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
