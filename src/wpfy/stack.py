from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
import subprocess

from . import traefik
from .php_runtime import DEFAULT_PHP_VERSION, PHP_IMAGE_REPOSITORY, php_image
from .site_layout import MARIADB_IMAGE, REDIS_IMAGE
from .site_runtime import RuntimeResult


HELPER_IMAGES = {
    "phpmyadmin": "phpmyadmin:5-apache",
    "adminer": "adminer:5",
    "composer": "composer:2",
}
HOST_TOOLS = ("netdata", "fail2ban", "ufw", "ngxblocker", "nanorc", "dashboard", "extplorer")


@dataclass(frozen=True, slots=True)
class StackInstallRequest:
    install_all: bool = False
    nginx: bool = False
    php_version: str | None = None
    mysql: bool = False
    mariadb: bool = False
    redis: bool = False
    wpcli: bool = False
    host_tools: tuple[str, ...] = ()
    helpers: tuple[str, ...] = ()
    mysqltuner: bool = False


@dataclass(frozen=True, slots=True)
class StackFact:
    name: str
    status: str
    message: str
    exit_code: int = 0


@dataclass(frozen=True, slots=True)
class StackResult:
    facts: tuple[StackFact, ...]
    exit_code: int = 0


@dataclass(frozen=True, slots=True)
class StackStatus:
    traefik: RuntimeResult
    docker_version: str | None
    images: tuple[str, ...]
    docker_error: str | None = None
    images_error: str | None = None

    @property
    def exit_code(self) -> int:
        return self.traefik.exit_code or (1 if self.docker_error or self.images_error else 0)


def _process_message(proc: subprocess.CompletedProcess[str], fallback: str) -> str:
    return proc.stderr.strip() or proc.stdout.strip() or fallback


def pull_image(image: str) -> StackFact:
    try:
        proc = subprocess.run(["docker", "pull", image], check=False, capture_output=True, text=True)
    except (OSError, subprocess.SubprocessError) as exc:
        return StackFact(image, "FAIL", f"error: {exc}", 1)
    if proc.returncode == 0:
        return StackFact(image, "OK", f"pulled {image}")
    error = _process_message(proc, "pull failed").splitlines()[-1]
    return StackFact(image, "FAIL", f"error: {error}", proc.returncode or 1)


def install(
    request: StackInstallRequest,
    *,
    progress: Callable[[str], None] | None = None,
) -> StackResult:
    notify = progress or (lambda _message: None)
    facts: list[StackFact] = []
    pulled_php_versions: set[str] = set()

    if request.install_all or request.nginx:
        notify("Starting shared Traefik edge proxy...")
        result = traefik.start_traefik()
        status_name = "SKIP" if result.skipped else "OK" if result.exit_code == 0 else "FAIL"
        facts.append(StackFact("Traefik", status_name, result.message, result.exit_code))

    php_version = request.php_version or (DEFAULT_PHP_VERSION if request.install_all else None)
    if php_version:
        notify(f"Pulling PHP {php_version} runtime image...")
        pulled = pull_image(php_image(php_version))
        facts.append(StackFact(f"PHP {php_version}", pulled.status, pulled.message, pulled.exit_code))
        if pulled.exit_code == 0:
            pulled_php_versions.add(php_version)

    for selected, name, image in (
        (request.install_all or request.mysql or request.mariadb, "MariaDB", MARIADB_IMAGE),
        (request.install_all or request.redis, "Redis", REDIS_IMAGE),
    ):
        if selected:
            notify(f"Pulling {image} image...")
            pulled = pull_image(image)
            facts.append(StackFact(name, pulled.status, pulled.message, pulled.exit_code))

    if request.wpcli:
        image = php_image(DEFAULT_PHP_VERSION)
        if DEFAULT_PHP_VERSION in pulled_php_versions:
            facts.append(StackFact("wp-cli", "OK", f"using {image} (bundled)"))
        else:
            notify(f"Pulling PHP {DEFAULT_PHP_VERSION} runtime image for WP-CLI...")
            pulled = pull_image(image)
            facts.append(StackFact("wp-cli", pulled.status, f"{pulled.message} (bundled)", pulled.exit_code))

    facts.extend(
        StackFact(tool, "WARN", "not applicable in Docker-first wpfy (use host-level tooling separately)")
        for tool in request.host_tools
        if tool in HOST_TOOLS
    )
    for helper in request.helpers:
        image = HELPER_IMAGES.get(helper)
        if image:
            notify(f"Pulling helper image {image}...")
            pulled = pull_image(image)
            facts.append(StackFact(helper, pulled.status, pulled.message, pulled.exit_code))
    if request.mysqltuner:
        facts.append(StackFact("mysqltuner", "WARN", "skipped; no vetted pinned container image yet"))

    exit_code = next((fact.exit_code for fact in reversed(facts) if fact.exit_code), 0)
    return StackResult(tuple(facts), exit_code)


def status() -> StackStatus:
    traefik_result = traefik.traefik_status()
    try:
        version = subprocess.run(
            ["docker", "version", "--format", "{{.Server.Version}}"],
            check=False,
            capture_output=True,
            text=True,
        )
        docker_version = version.stdout.strip() if version.returncode == 0 and version.stdout.strip() else None
        docker_error = None if version.returncode == 0 else _process_message(version, "Docker status failed")
    except (OSError, subprocess.SubprocessError) as exc:
        docker_version, docker_error = None, str(exc)
    try:
        images_proc = subprocess.run(
            ["docker", "images", "--format", "{{.Repository}}:{{.Tag}}", f"{PHP_IMAGE_REPOSITORY}*"],
            check=False,
            capture_output=True,
            text=True,
        )
        images = tuple(images_proc.stdout.splitlines()) if images_proc.returncode == 0 else ()
        images_error = None if images_proc.returncode == 0 else _process_message(images_proc, "image status failed")
    except (OSError, subprocess.SubprocessError) as exc:
        images, images_error = (), str(exc)
    return StackStatus(traefik_result, docker_version, images, docker_error, images_error)


def remove() -> RuntimeResult:
    return traefik.stop_traefik()


def upgrade() -> StackResult:
    compose_file = traefik.traefik_compose_path()
    if not compose_file.exists():
        fact = StackFact(
            "Traefik",
            "FAIL",
            "not installed; run 'wpfy stack install --nginx' first",
            2,
        )
        return StackResult((fact,), 2)
    try:
        pull = subprocess.run(
            ["docker", "compose", "-f", str(compose_file), "pull"],
            cwd=traefik.traefik_dir(), check=False, capture_output=True, text=True,
        )
        if pull.returncode != 0:
            message = _process_message(pull, "pull failed")
            fact = StackFact("Traefik", "FAIL", f"pull failed: {message}", pull.returncode)
            return StackResult((fact,), pull.returncode)
        with traefik.traefik_transaction():
            restart = subprocess.run(
                ["docker", "compose", "-f", str(compose_file), "up", "-d"],
                cwd=traefik.traefik_dir(), check=False, capture_output=True, text=True, timeout=120,
            )
            if restart.returncode == 0:
                health = traefik._wait_for_traefik_healthy()
                if health.exit_code != 0:
                    return StackResult((StackFact("Traefik", "FAIL", health.message, health.exit_code),), health.exit_code)
                traefik._record_applied_state(traefik.traefik_config_path().read_text(encoding="utf-8"))
    except (OSError, subprocess.SubprocessError) as exc:
        return StackResult((StackFact("Traefik", "FAIL", str(exc), 1),), 1)
    if restart.returncode != 0:
        message = _process_message(restart, "restart failed")
        fact = StackFact("Traefik", "FAIL", f"restart failed: {message}", restart.returncode)
        return StackResult((fact,), restart.returncode)
    return StackResult((
        StackFact("Traefik", "OK", "pulled latest images and restarted"),
        StackFact("pull", "OK", "complete"),
    ))


def purge(*, force: bool) -> StackResult:
    if not force:
        return StackResult((StackFact("Traefik", "FAIL", "--force is required", 2),), 2)
    stopped = traefik.stop_traefik()
    status_name = "SKIP" if stopped.skipped else "OK" if stopped.exit_code == 0 else "FAIL"
    stop_fact = StackFact("Traefik", status_name, stopped.message, stopped.exit_code)
    if stopped.exit_code != 0 or stopped.skipped:
        return StackResult((stop_fact,), stopped.exit_code or 1)

    facts = [stop_fact]
    compose_file = traefik.traefik_compose_path()
    if compose_file.exists():
        try:
            proc = subprocess.run(
                ["docker", "compose", "-f", str(compose_file), "down", "--volumes", "--remove-orphans"],
                cwd=traefik.traefik_dir(), check=False, capture_output=True, text=True,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            return StackResult((*facts, StackFact("compose project", "FAIL", str(exc), 1)), 1)
        if proc.returncode != 0:
            message = _process_message(proc, "docker compose down failed")
            fact = StackFact("compose project", "FAIL", message, proc.returncode)
            return StackResult((*facts, fact), proc.returncode)
        facts.append(StackFact("compose project", "OK", "removed"))
    facts.append(StackFact(
        "pulled images",
        "INFO",
        f"docker rmi {php_image(DEFAULT_PHP_VERSION)} {MARIADB_IMAGE} {REDIS_IMAGE} {traefik.TRAEFIK_IMAGE}",
    ))
    return StackResult(tuple(facts))
