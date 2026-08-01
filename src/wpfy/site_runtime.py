from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
import os
import shutil
import subprocess
import time

from .site_definition import WORDPRESS_FLAVORS, SiteDefinition
from .site_paths import (
    app_dir,
    env_path,
    domain_to_project,
    healthcheck_path,
    nginx_conf_path,
    read_env,
    site_dir,
    site_exists,
    validate_domain,
)


@dataclass(frozen=True, slots=True)
class RuntimeResult:
    exit_code: int
    message: str
    ran: bool = False
    skipped: bool = False


@dataclass(frozen=True, slots=True)
class HealthResult:
    domain: str
    scaffold_ready: bool
    bootstrap_ready: bool
    runtime_ready: bool
    http_ready: bool
    status: str
    message: str


@dataclass(frozen=True, slots=True)
class ProcessResult:
    exit_code: int
    stdout: str = ""
    stderr: str = ""
    ran: bool = False
    skipped: bool = False


@dataclass(frozen=True, slots=True)
class LogResetResult:
    stop: RuntimeResult
    restart: RuntimeResult | None = None

    @property
    def exit_code(self) -> int:
        if self.stop.exit_code != 0 or self.stop.skipped:
            return self.stop.exit_code or 1
        if self.restart is None:
            return 1
        return self.restart.exit_code or (1 if self.restart.skipped else 0)


def app_health_ok(status: str, bootstrap_ready: bool, runtime_ready: bool) -> bool | None:
    if not bootstrap_ready:
        return False
    if runtime_ready or status == "ready":
        return True
    if status == "down":
        return False
    return None


def runtime_skip_requested() -> bool:
    return os.environ.get("WPFY_SKIP_RUNTIME", "0") == "1"


@lru_cache(maxsize=1)
def docker_available() -> bool:
    docker = shutil.which("docker")
    if not docker:
        return False
    proc = subprocess.run([docker, "compose", "version"], check=False, capture_output=True, text=True)
    return proc.returncode == 0


def compose_command(
    domain: str,
    *args: str,
    input_text: str | None = None,
    timeout: float | None = None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["docker", "compose", *args],
        cwd=site_dir(domain),
        check=False,
        capture_output=True,
        text=True,
        input=input_text,
        timeout=timeout,
    )


def wp_cli_command(
    domain: str,
    *args: str,
    input_text: str | None = None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["docker", "compose", "--profile", "cli", "run", "--rm", "-T", "wpcli", *args],
        cwd=site_dir(domain),
        check=False,
        capture_output=True,
        text=True,
        input=input_text,
    )


def start_site_runtime(domain: str) -> RuntimeResult:
    if runtime_skip_requested():
        return RuntimeResult(0, "runtime skipped by WPFY_SKIP_RUNTIME=1", skipped=True)
    if not docker_available():
        return RuntimeResult(0, "runtime skipped because Docker or Compose is unavailable", skipped=True)
    # --remove-orphans reconciles containers the site no longer declares. compose.yaml
    # is regenerated in full from the SiteDefinition, so anything in the project that
    # is not a defined service is stale by construction — without this, disabling the
    # Redis object cache left its container running outside wpfy's lifecycle. The
    # one-off `...-wpcli-run-...` containers are safe: wpcli is itself a defined
    # service, so they are never orphans.
    proc = compose_command(domain, "up", "-d", "--remove-orphans")
    if proc.returncode != 0:
        message = proc.stderr.strip() or proc.stdout.strip() or "docker compose up failed"
        return RuntimeResult(proc.returncode, message)
    message = proc.stdout.strip() or proc.stderr.strip() or "compose project started"
    return RuntimeResult(0, message, ran=True)


def stop_site_runtime(domain: str, *, remove_volumes: bool = False) -> RuntimeResult:
    if runtime_skip_requested() or not docker_available():
        return RuntimeResult(0, "runtime stop skipped", skipped=True)
    args = ("down", "-v") if remove_volumes else ("down",)
    proc = compose_command(domain, *args)
    if proc.returncode != 0:
        message = proc.stderr.strip() or proc.stdout.strip() or "docker compose down failed"
        return RuntimeResult(proc.returncode, message)
    message = proc.stdout.strip() or proc.stderr.strip() or "compose project stopped"
    return RuntimeResult(0, message, ran=True)


def runtime_status(domain: str) -> RuntimeResult:
    if runtime_skip_requested() or not docker_available():
        return RuntimeResult(0, "runtime status unavailable (Docker/Compose not available)", skipped=True)
    proc = compose_command(domain, "ps")
    if proc.returncode != 0:
        message = proc.stderr.strip() or proc.stdout.strip() or "docker compose ps failed"
        return RuntimeResult(proc.returncode, message)
    message = proc.stdout.strip() or proc.stderr.strip() or "no running containers"
    return RuntimeResult(0, message, ran=True)


def site_compose_project(domain: str) -> str:
    """The site's Compose project, from the authoritative `.env` wpfy itself writes.

    A container's `com.docker.compose.project` label is mutable runtime state: anything
    that ran `docker compose up` with COMPOSE_PROJECT_NAME set overrides it, and acting
    on that value makes wpfy chase a project it never created. `.env` is regenerated by
    `ensure_site_scaffold`, so it always names the project wpfy owns.
    """
    return read_env(env_path(domain)).get("COMPOSE_PROJECT_NAME") or domain_to_project(domain)


def restart_site_service(domain: str, service: str) -> RuntimeResult:
    """Restart one service in this site's isolated Compose project."""
    if runtime_skip_requested() or not docker_available():
        return RuntimeResult(0, "service restart skipped (Docker/Compose not available)", skipped=True)
    proc = compose_command(domain, "--project-name", site_compose_project(domain), "restart", service)
    if proc.returncode != 0:
        message = proc.stderr.strip() or proc.stdout.strip() or "docker compose restart failed"
        return RuntimeResult(proc.returncode, message)
    return RuntimeResult(0, proc.stdout.strip() or proc.stderr.strip() or f"{service} restarted", ran=True)


def list_site_services(domain: str, services: tuple[str, ...]) -> list[dict[str, str]]:
    """Return status rows for the explicitly named containers belonging to one site."""
    if runtime_skip_requested() or not docker_available():
        return [{"name": service, "status": "unavailable"} for service in services]
    project = domain_to_project(domain)
    return [
        {"name": service, "status": (_container_healths([f"{project}-{service}"]) or ["unknown"])[0]}
        for service in services
    ]


def _compose_service_ids(domain: str, service: str) -> list[str]:
    proc = compose_command(domain, "ps", "-q", service)
    if proc.returncode != 0:
        return []
    return [line.strip() for line in proc.stdout.splitlines() if line.strip()]


def _container_healths(container_ids: list[str]) -> list[str]:
    if not container_ids:
        return []
    docker = shutil.which("docker")
    if not docker:
        return ["unknown"] * len(container_ids)
    try:
        proc = subprocess.run(
            [
                docker,
                "inspect",
                "--format",
                "{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}",
                *container_ids,
            ],
            check=False,
            capture_output=True,
            text=True,
        )
    except (OSError, subprocess.SubprocessError):
        return ["unknown"] * len(container_ids)
    if proc.returncode != 0:
        return ["unknown"] * len(container_ids)
    statuses = [line.strip().lower() or "unknown" for line in proc.stdout.splitlines()]
    return statuses if len(statuses) == len(container_ids) else ["unknown"] * len(container_ids)


def _compose_service_health(domain: str, service: str) -> list[str]:
    return _container_healths(_compose_service_ids(domain, service))


def _compose_exec(domain: str, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["docker", "compose", "exec", "-T", *args],
        cwd=site_dir(domain),
        check=False,
        capture_output=True,
        text=True,
    )


def http_probe_site(domain: str) -> RuntimeResult:
    if runtime_skip_requested() or not docker_available():
        return RuntimeResult(0, "http probe skipped", skipped=True)
    proc = _compose_exec(domain, "web", "sh", "-lc", "wget -qO- http://127.0.0.1:8080/healthz.html")
    if proc.returncode != 0:
        message = proc.stderr.strip() or proc.stdout.strip() or "http probe failed"
        return RuntimeResult(proc.returncode, message)
    if "wpfy-ok" not in proc.stdout.strip():
        return RuntimeResult(1, "http probe returned unexpected body")
    return RuntimeResult(0, "http probe passed", ran=True)


def nginx_config_test(domain: str) -> RuntimeResult:
    if runtime_skip_requested() or not docker_available():
        return RuntimeResult(0, "nginx config test skipped", skipped=True)
    proc = _compose_exec(domain, "web", "nginx", "-t")
    output = "\n".join(part.strip() for part in (proc.stdout, proc.stderr) if part and part.strip())
    if proc.returncode != 0:
        return RuntimeResult(proc.returncode or 1, output or "nginx configuration test failed", ran=True)
    return RuntimeResult(0, output or "nginx configuration test passed", ran=True)


def site_health(domain: str) -> HealthResult:
    validate_domain(domain)
    scaffold_ready = site_exists(domain)
    bootstrap_ready = False

    if not scaffold_ready:
        return HealthResult(domain, False, False, False, False, "missing", f"site not found: {domain}")

    definition = SiteDefinition.from_env(domain, read_env(env_path(domain)))
    flavor = definition.flavor
    app_root = app_dir(domain)
    common_ready = healthcheck_path(domain).exists() and nginx_conf_path(domain).exists()
    if flavor in WORDPRESS_FLAVORS:
        bootstrap_ready = common_ready and (app_root / "index.php").exists() and (app_root / "wp-config.php").exists()
    elif flavor == "html":
        bootstrap_ready = common_ready and (app_root / "index.html").exists()
    else:
        bootstrap_ready = common_ready and (app_root / "index.php").exists()

    if runtime_skip_requested() or not docker_available():
        status = "degraded" if bootstrap_ready else "needs-bootstrap"
        return HealthResult(
            domain, scaffold_ready, bootstrap_ready, False, False, status,
            "runtime unavailable (Docker/Compose not available)",
        )

    web_ids = _compose_service_ids(domain, "web")
    app_ids = _compose_service_ids(domain, "app")
    needs_mysql = definition.use_mysql
    needs_redis = definition.object_cache == "redis"
    db_ids = _compose_service_ids(domain, "db") if needs_mysql else []
    redis_ids = _compose_service_ids(domain, "redis") if needs_redis else []
    health = _container_healths(web_ids + app_ids + db_ids + redis_ids)
    web_end = len(web_ids)
    app_end = web_end + len(app_ids)
    db_end = app_end + len(db_ids)
    web_health = health[:web_end]
    app_health = health[web_end:app_end]
    db_health = health[app_end:db_end]
    redis_health = health[db_end:]
    web_ok = bool(web_ids) and all(status == "healthy" for status in web_health)
    app_ok = bool(app_ids) and all(status == "healthy" for status in app_health)
    db_ok = (not needs_mysql) or (bool(db_ids) and all(status == "healthy" for status in db_health))
    redis_ok = (not needs_redis) or (bool(redis_ids) and all(status == "healthy" for status in redis_health))
    nginx_config = (
        nginx_config_test(domain)
        if web_ids
        else RuntimeResult(1, "nginx config test not run (web service is not running)")
    )
    nginx_config_ok = nginx_config.ran and nginx_config.exit_code == 0
    http_probe = http_probe_site(domain)
    http_ready = http_probe.ran and http_probe.exit_code == 0
    runtime_ready = web_ok and app_ok and db_ok and redis_ok and nginx_config_ok and http_ready

    if runtime_ready:
        status = "ready" if bootstrap_ready else "running"
        message = (
            f"web={len(web_ids)} app={len(app_ids)} db={len(db_ids)} redis={len(redis_ids)} "
            "nginx_config=ok http=ok"
        )
    elif web_ok and app_ok:
        status = "partial"
        message = (
            f"web={len(web_ids)} app={len(app_ids)} db={len(db_ids)} redis={len(redis_ids)} "
            f"nginx_config={'ok' if nginx_config_ok else nginx_config.message} "
            f"http={'ok' if http_ready else http_probe.message} "
            f"app_health={','.join(app_health) or 'unknown'} web_health={','.join(web_health) or 'unknown'} "
            f"db_health={','.join(db_health) or 'unknown'} redis_health={','.join(redis_health) or 'unknown'}"
        )
    else:
        status = "down"
        message = (
            f"no healthy compose services app_health={','.join(app_health) or 'unknown'} "
            f"web_health={','.join(web_health) or 'unknown'} db_health={','.join(db_health) or 'unknown'} "
            f"redis_health={','.join(redis_health) or 'unknown'} "
            f"nginx_config={'ok' if nginx_config_ok else nginx_config.message} "
            f"http={'ok' if http_ready else http_probe.message}"
        )

    if not bootstrap_ready:
        status = "needs-bootstrap" if status == "down" else f"{status}-bootstrap"
        message = f"{message}; site app files are not bootstrapped"

    return HealthResult(domain, scaffold_ready, bootstrap_ready, runtime_ready, http_ready, status, message)


def wait_for_service(domain: str, service: str, timeout_seconds: int = 60) -> RuntimeResult:
    if runtime_skip_requested() or not docker_available():
        return RuntimeResult(0, f"{service} wait skipped (Docker/Compose not available)", skipped=True)
    deadline = time.monotonic() + timeout_seconds
    last_status = "unknown"
    while time.monotonic() < deadline:
        statuses = _compose_service_health(domain, service)
        if statuses and all(status in {"healthy", "running"} for status in statuses):
            return RuntimeResult(0, f"{service} ready", ran=True)
        if statuses:
            last_status = ",".join(statuses)
        time.sleep(2)
    return RuntimeResult(1, f"{service} not ready after {timeout_seconds}s (last status: {last_status})")


LOG_SERVICES = frozenset({"web", "app", "db", "redis", "sftp"})


def site_logs(
    domain: str,
    *,
    services: tuple[str, ...] = (),
    lines: int = 100,
    follow: bool = False,
    no_color: bool = False,
) -> ProcessResult:
    unknown = set(services) - LOG_SERVICES
    if unknown:
        raise ValueError(f"unknown log service: {sorted(unknown)[0]}")
    if runtime_skip_requested() or not docker_available():
        return ProcessResult(1, stderr="runtime unavailable (Docker/Compose not available)", skipped=True)
    command = ["docker", "compose", "logs", "--tail", str(lines)]
    if no_color:
        command.append("--no-color")
    if follow:
        command.append("--follow")
    command.extend(services)
    try:
        proc = subprocess.run(
            command,
            cwd=site_dir(domain),
            check=False,
            capture_output=not follow,
            text=not follow,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return ProcessResult(1, stderr=str(exc))
    return ProcessResult(
        proc.returncode,
        proc.stdout or "" if not follow else "",
        proc.stderr or "" if not follow else "",
        ran=True,
    )


def reset_site_logs(domain: str) -> LogResetResult:
    stop = stop_site_runtime(domain)
    if stop.exit_code != 0 or stop.skipped:
        return LogResetResult(stop)
    return LogResetResult(stop, start_site_runtime(domain))


def _wp_cli_args(args: tuple[str, ...], *, interactive: bool) -> list[str]:
    wp_args = [arg for arg in args if arg != "--allow-root"]
    wp_args.append("--allow-root")
    command = ["docker", "compose", "--profile", "cli", "run", "--rm"]
    if not interactive:
        command.append("-T")
    return [*command, "wpcli", *wp_args]


def run_wp_cli(domain: str, *args: str, interactive: bool = False) -> ProcessResult:
    if runtime_skip_requested() or not docker_available():
        return ProcessResult(1, stderr="runtime unavailable (Docker/Compose not available)", skipped=True)
    try:
        proc = subprocess.run(
            _wp_cli_args(args, interactive=interactive),
            cwd=site_dir(domain),
            check=False,
            capture_output=not interactive,
            text=not interactive,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return ProcessResult(1, stderr=str(exc))
    return ProcessResult(
        proc.returncode,
        proc.stdout or "" if not interactive else "",
        proc.stderr or "" if not interactive else "",
        ran=True,
    )
