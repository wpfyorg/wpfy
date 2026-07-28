from __future__ import annotations

from datetime import datetime, timedelta
import importlib
import json
import os
from pathlib import Path
import re
import subprocess
import tarfile

import pytest


DOMAIN = "cron.example.com"
HOSTILE_SERVICES = (
    "victim-example-app",
    "../victim.example/app",
    "app; rm -rf /",
    "app\nwpfy_injected",
    "app\x00",
    "",
    "wpfy-traefik",
)


def _seed_site(
    paths,
    *,
    domain: str = DOMAIN,
    flavor: str = "wp",
    redis: bool = False,
    sftp: bool = False,
    adminer: bool = False,
) -> Path:
    root = Path(paths.sites_dir) / domain
    root.mkdir(parents=True, exist_ok=True)
    values = [
        f"DOMAIN={domain}",
        f"COMPOSE_PROJECT_NAME={domain.replace('.', '-')}",
        f"SITE_FLAVOR={flavor}",
        "APP_ROOT=/var/www/html",
        "PHP_VERSION=8.4",
        "SITE_UID=1700",
        "PAGE_CACHE=none",
    ]
    if flavor in {"mysql", "wp", "wpfc", "wpredis", "wpsc", "wprocket", "wpce", "wpsubdir", "wpsubdomain"}:
        values.extend([
            "DB_NAME=cron",
            "DB_USER=cron",
            "DB_PASSWORD=cron-password",
            "DB_ROOT_PASSWORD=cron-root-password",
        ])
    if redis:
        values.append("REDIS_ENABLED=1")
    if sftp:
        values.extend(["SFTP_PASSWORD=sftp-password", "SFTP_PORT=2222"])
    if adminer:
        values.append("ADMINER_PORT=9080")
    (root / ".env").write_text("\n".join(values) + "\n", encoding="utf-8")
    (root / "compose.yaml").write_text("services: {}\n", encoding="utf-8")
    return root


def _reload_site_cron():
    import wpfy.events
    import wpfy.site_cron
    import wpfy.site_layout
    import wpfy.site_paths

    importlib.reload(wpfy.site_paths)
    importlib.reload(wpfy.site_layout)
    importlib.reload(wpfy.events)
    return importlib.reload(wpfy.site_cron)


def test_job_lifecycle_persists_exact_spec_and_returns_safe_id(tmp_wpfy_home):
    from wpfy import site_cron

    root = _seed_site(tmp_wpfy_home)
    command = "printf 'one;two'\necho done"

    assert site_cron.load_cron(DOMAIN) == []
    job = site_cron.add_job(
        DOMAIN,
        schedule="  */15   8-18/2  * * 1,3,5  ",
        command=command,
        service="app",
    )

    assert re.fullmatch(r"[a-f0-9]{12}", str(job["id"]))
    assert job == {
        "id": job["id"],
        "schedule": "*/15 8-18/2 * * 1,3,5",
        "command": command,
        "service": "app",
        "enabled": True,
        "timeout": site_cron.DEFAULT_TIMEOUT,
    }
    assert site_cron.load_cron(DOMAIN) == [job]
    assert json.loads((root / "cron.json").read_text(encoding="utf-8")) == [job]
    assert (root / "cron.json").stat().st_mode & 0o777 == 0o600

    site_cron.set_enabled(DOMAIN, str(job["id"]), False)
    assert site_cron.load_cron(DOMAIN)[0]["enabled"] is False

    site_cron.remove_job(DOMAIN, str(job["id"]))
    assert site_cron.load_cron(DOMAIN) == []


@pytest.mark.parametrize(
    "schedule",
    (
        "",
        "* * * *",
        "* * * * * *",
        "60 * * * *",
        "* 24 * * *",
        "* * 0 * *",
        "* * 32 * *",
        "* * * 0 *",
        "* * * 13 *",
        "* * * * 8",
        "*/0 * * * *",
        "*/-1 * * * *",
        "20-10 * * * *",
        "abc * * * *",
        "* * * * *; rm -rf /",
        "*\n* * * *",
        "*\r* * * *",
        "1,,2 * * * *",
        "1/2 * * * *",
        "*/2/3 * * * *",
    ),
)
def test_malformed_schedule_is_rejected_without_changing_state(tmp_wpfy_home, schedule):
    from wpfy import site_cron

    root = _seed_site(tmp_wpfy_home)
    site_cron.add_job(DOMAIN, schedule="0 1 * * *", command="echo existing", service="app")
    before = (root / "cron.json").read_bytes()

    with pytest.raises((TypeError, ValueError)):
        site_cron.add_job(DOMAIN, schedule=schedule, command="echo rejected", service="app")

    assert (root / "cron.json").read_bytes() == before


def test_command_nul_is_rejected_but_shell_syntax_is_stored_verbatim(tmp_wpfy_home):
    from wpfy import site_cron

    root = _seed_site(tmp_wpfy_home)
    command = """sh -c 'printf %s "$HOME;$(id)"'
echo complete"""
    job = site_cron.add_job(DOMAIN, schedule="* * * * *", command=command, service="app")
    before = (root / "cron.json").read_bytes()

    assert job["command"] == command
    with pytest.raises(ValueError, match="NUL"):
        site_cron.add_job(DOMAIN, schedule="* * * * *", command="echo bad\x00tail", service="app")
    assert (root / "cron.json").read_bytes() == before


def test_service_whitelist_tracks_services_emitted_for_the_site(tmp_wpfy_home):
    from wpfy import site_cron

    _seed_site(tmp_wpfy_home, redis=True, sftp=True, adminer=True)
    for service in ("web", "app", "db", "redis", "sftp", "adminer"):
        site_cron.add_job(DOMAIN, schedule="* * * * *", command=f"echo {service}", service=service)

    stored = site_cron.load_cron(DOMAIN)
    assert {job["service"] for job in stored} == {"web", "app", "db", "redis", "sftp", "adminer"}


def test_wpcli_profile_service_is_not_a_cron_target(tmp_wpfy_home):
    from wpfy import site_cron

    _seed_site(tmp_wpfy_home)

    with pytest.raises(ValueError, match="not available"):
        site_cron.add_job(DOMAIN, schedule="* * * * *", command="wp cron event run --due-now", service="wpcli")


def test_loaded_wpcli_jobs_migrate_to_app_without_hiding_other_jobs(tmp_wpfy_home):
    from wpfy import site_cron

    root = _seed_site(tmp_wpfy_home)
    jobs = [
        {
            "id": "111111111111",
            "schedule": "* * * * *",
            "command": "wp cron event run --due-now",
            "service": "wpcli",
            "enabled": True,
            "timeout": 30,
        },
        {
            "id": "222222222222",
            "schedule": "* * * * *",
            "command": "echo healthy",
            "service": "app",
            "enabled": True,
            "timeout": 30,
        },
    ]
    (root / "cron.json").write_text(json.dumps(jobs), encoding="utf-8")

    loaded = site_cron.load_cron(DOMAIN)

    assert [job["service"] for job in loaded] == ["app", "app"]
    assert [job["command"] for job in loaded] == ["wp cron event run --due-now", "echo healthy"]


def test_service_whitelist_refuses_unconfigured_targets_fail_closed(tmp_wpfy_home):
    from wpfy import site_cron

    root = _seed_site(tmp_wpfy_home, flavor="html", adminer=True)
    baseline = site_cron.add_job(DOMAIN, schedule="* * * * *", command="echo safe", service="app")
    before = (root / "cron.json").read_bytes()

    for service in ("db", "redis", "sftp", "adminer"):
        with pytest.raises((TypeError, ValueError)):
            site_cron.add_job(DOMAIN, schedule="* * * * *", command="echo refused", service=service)
        assert (root / "cron.json").read_bytes() == before

    assert site_cron.load_cron(DOMAIN) == [baseline]


@pytest.mark.parametrize("service", HOSTILE_SERVICES)
def test_each_hostile_service_is_refused_without_state_change(tmp_wpfy_home, service):
    from wpfy import site_cron

    root = _seed_site(tmp_wpfy_home)
    before = site_cron.load_cron(DOMAIN)
    before_bytes = (root / "cron.json").read_bytes() if (root / "cron.json").exists() else None

    with pytest.raises((TypeError, ValueError)):
        site_cron.add_job(DOMAIN, schedule="* * * * *", command="echo refused", service=service)

    assert site_cron.load_cron(DOMAIN) == before
    assert ((root / "cron.json").read_bytes() if (root / "cron.json").exists() else None) == before_bytes


def test_save_rejects_duplicate_ids_and_invalid_shape_without_replacing_state(tmp_wpfy_home):
    from wpfy import site_cron

    root = _seed_site(tmp_wpfy_home)
    job = site_cron.add_job(DOMAIN, schedule="* * * * *", command="echo safe", service="app")
    before = (root / "cron.json").read_bytes()

    with pytest.raises(ValueError, match="unique"):
        site_cron.save_cron(DOMAIN, [job, dict(job)])
    with pytest.raises(ValueError, match="exactly"):
        site_cron.save_cron(DOMAIN, [{**job, "extra": "field"}])

    assert (root / "cron.json").read_bytes() == before


def test_cron_state_symlink_is_refused_without_touching_target(tmp_wpfy_home):
    from wpfy import site_cron

    root = _seed_site(tmp_wpfy_home)
    external = root.parent / "external.json"
    external.write_text("outside\n", encoding="utf-8")
    (root / "cron.json").symlink_to(external)

    with pytest.raises(OSError):
        site_cron.load_cron(DOMAIN)
    with pytest.raises(OSError):
        site_cron.add_job(DOMAIN, schedule="* * * * *", command="echo safe", service="app")

    assert external.read_text(encoding="utf-8") == "outside\n"


@pytest.mark.parametrize(
    "schedule,moment,expected",
    (
        ("* * * * *", datetime(2026, 1, 1, 0, 0), True),
        ("0 * * * *", datetime(2026, 1, 1, 0, 0), True),
        ("59 * * * *", datetime(2026, 1, 1, 0, 59), True),
        ("0 * * * *", datetime(2026, 1, 1, 0, 59), False),
        ("* 0 * * *", datetime(2026, 1, 1, 0, 37), True),
        ("* 23 * * *", datetime(2026, 1, 1, 23, 37), True),
        ("* 23 * * *", datetime(2026, 1, 1, 22, 37), False),
        ("* * 1 * *", datetime(2026, 1, 1, 12, 0), True),
        ("* * 31 * *", datetime(2026, 1, 31, 12, 0), True),
        ("* * 31 * *", datetime(2026, 2, 1, 12, 0), False),
        ("* * * 1 *", datetime(2026, 1, 20, 12, 0), True),
        ("* * * 12 *", datetime(2026, 12, 20, 12, 0), True),
        ("* * * 12 *", datetime(2026, 11, 20, 12, 0), False),
        ("* * * * 0", datetime(2026, 2, 1, 12, 0), True),
        ("* * * * 7", datetime(2026, 2, 1, 12, 0), True),
        ("* * * * 1", datetime(2026, 2, 2, 12, 0), True),
        ("0,15,45 * * * *", datetime(2026, 1, 1, 12, 15), True),
        ("0,15,45 * * * *", datetime(2026, 1, 1, 12, 30), False),
        ("10-20 * * * *", datetime(2026, 1, 1, 12, 10), True),
        ("10-20 * * * *", datetime(2026, 1, 1, 12, 20), True),
        ("10-20 * * * *", datetime(2026, 1, 1, 12, 21), False),
        ("*/5 * * * *", datetime(2026, 1, 1, 12, 45), True),
        ("*/5 * * * *", datetime(2026, 1, 1, 12, 32), False),
        ("10-20/3 * * * *", datetime(2026, 1, 1, 12, 19), True),
        ("10-20/3 * * * *", datetime(2026, 1, 1, 12, 20), False),
        ("* 8-20/4 * * *", datetime(2026, 1, 1, 16, 0), True),
        ("* 8-20/4 * * *", datetime(2026, 1, 1, 18, 0), False),
        ("* * */5 * *", datetime(2026, 1, 6, 0, 0), True),
        ("* * */5 * *", datetime(2026, 1, 5, 0, 0), False),
        ("* * * */3 *", datetime(2026, 7, 1, 0, 0), True),
        ("* * * */3 *", datetime(2026, 8, 1, 0, 0), False),
        ("* * * * 1-5/2", datetime(2026, 7, 24, 0, 0), True),
        ("* * * * 1-5/2", datetime(2026, 7, 23, 0, 0), False),
    ),
)
def test_schedule_matcher_syntax_and_field_boundaries(schedule, moment, expected):
    from wpfy.site_cron import schedule_matches

    assert schedule_matches(schedule, moment) is expected


def test_day_of_month_and_day_of_week_use_traditional_cron_or_semantics():
    from wpfy.site_cron import schedule_matches

    schedule = "0 0 13 * 1"

    assert schedule_matches(schedule, datetime(2026, 7, 20, 0, 0)) is True  # Monday, not the 13th.
    assert schedule_matches(schedule, datetime(2026, 8, 13, 0, 0)) is True  # The 13th, not Monday.
    assert schedule_matches(schedule, datetime(2026, 8, 14, 0, 0)) is False
    assert schedule_matches("0 0 13 * *", datetime(2026, 7, 20, 0, 0)) is False
    assert schedule_matches("0 0 * * 1", datetime(2026, 8, 13, 0, 0)) is False


def test_validate_schedule_normalizes_spacing_and_accepts_sunday_alias():
    from wpfy.site_cron import validate_schedule

    assert validate_schedule("\t0,30   0-23/2  1-31 1,12 0,7\t") == "0,30 0-23/2 1-31 1,12 0,7"


def _reference_values(expression: str, minimum: int, maximum: int, *, weekday: bool = False) -> set[int]:
    selected: set[int] = set()
    for part in expression.split(","):
        step = 1
        base = part
        if "/" in part:
            base, step_text = part.split("/")
            step = int(step_text)
        if base == "*":
            first, last = minimum, maximum
        elif "-" in base:
            first_text, last_text = base.split("-")
            first, last = int(first_text), int(last_text)
        else:
            first = last = int(base)
        for value in range(first, last + 1, step):
            selected.add(0 if weekday and value == 7 else value)
    return selected


def _reference_matches(schedule: str, moment: datetime) -> bool:
    expressions = schedule.split()
    limits = ((0, 59), (0, 23), (1, 31), (1, 12), (0, 7))
    values = [
        _reference_values(expression, low, high, weekday=index == 4)
        for index, (expression, (low, high)) in enumerate(zip(expressions, limits))
    ]
    if moment.minute not in values[0] or moment.hour not in values[1] or moment.month not in values[3]:
        return False
    cron_weekday = (moment.weekday() + 1) % 7
    dom_matches = moment.day in values[2]
    dow_matches = cron_weekday in values[4]
    if expressions[2] != "*" and expressions[4] != "*":
        return dom_matches or dow_matches
    if expressions[2] != "*":
        return dom_matches
    if expressions[4] != "*":
        return dow_matches
    return True


def test_matcher_cross_checks_against_independent_naive_reference():
    from wpfy.site_cron import schedule_matches

    schedules = (
        "* * * * *",
        "*/5 * * * *",
        "7,19,43 0-23/4 * * *",
        "10-50/7 3,17 * * *",
        "0 0 31 1 *",
        "0 0 1 2 *",
        "0 12 * * 0,7",
        "5 8 31 1 0",
        "45 23 1-31/5 1,2 1-5/2",
    )
    starts = (datetime(2026, 1, 31), datetime(2026, 2, 1))

    for start in starts:
        for minute in range(24 * 60):
            moment = start + timedelta(minutes=minute)
            for schedule in schedules:
                assert schedule_matches(schedule, moment) is _reference_matches(schedule, moment), (
                    schedule,
                    moment,
                )


def test_scaffold_regeneration_preserves_cron_state_byte_for_byte(tmp_wpfy_home):
    import wpfy.site_layout
    from wpfy import site_cron

    importlib.reload(wpfy.site_layout)
    spec = wpfy.site_layout.SiteSpec(domain=DOMAIN, flavor="wp", use_mysql=True, use_redis=False)
    wpfy.site_layout.ensure_site_scaffold(spec)
    site_cron.add_job(DOMAIN, schedule="*/10 * * * *", command="echo regenerate", service="app")
    cron_path = Path(tmp_wpfy_home.sites_dir) / DOMAIN / "cron.json"
    before = cron_path.read_bytes()

    wpfy.site_layout.ensure_site_scaffold(spec)

    assert cron_path.read_bytes() == before


def test_backup_archive_includes_cron_state(tmp_wpfy_home, monkeypatch):
    import wpfy.site_layout
    from wpfy import site_cron

    importlib.reload(wpfy.site_layout)
    _seed_site(tmp_wpfy_home)
    site_cron.add_job(DOMAIN, schedule="0 3 * * *", command="echo backup", service="app")
    monkeypatch.setattr(wpfy.site_layout, "docker_available", lambda: False)

    result = wpfy.site_layout.backup_site(DOMAIN)

    assert result.exit_code == 0
    archives = sorted((Path(tmp_wpfy_home.state_dir) / "backups" / DOMAIN).glob("*.tar.gz"))
    assert len(archives) == 1
    with tarfile.open(archives[0], "r:gz") as archive:
        assert f"{DOMAIN}/cron.json" in archive.getnames()


def test_due_job_uses_in_container_timeout(tmp_wpfy_home, monkeypatch):
    site_cron = _reload_site_cron()
    _seed_site(tmp_wpfy_home)
    job = site_cron.add_job(
        DOMAIN,
        schedule="* * * * *",
        command="printf '%s\\n' \"$HOME;$(id -u)\"",
        service="app",
        timeout=37,
    )
    calls = []

    def compose(domain, *args, **kwargs):
        calls.append((domain, args, kwargs))
        stdout = "app-container-id\n" if "ps" in args else "done\n"
        return subprocess.CompletedProcess(args, 0, stdout, "")

    monkeypatch.setattr(site_cron, "list_sites", lambda: [{"domain": DOMAIN}])
    monkeypatch.setattr(site_cron, "runtime_skip_requested", lambda: False)
    monkeypatch.setattr(site_cron, "docker_available", lambda: True)
    monkeypatch.setattr(site_cron, "compose_command", compose)

    result = site_cron.run_due(datetime(2026, 7, 24, 10, 30))

    assert result.exit_code == 0
    assert result.jobs[0].job_id == job["id"]
    assert len(calls) == 1
    domain, args, kwargs = calls[0]
    assert domain == DOMAIN
    assert args[:11] == (
        "--project-name",
        "cron-example-com",
        "exec",
        "-T",
        "app",
        "timeout",
        "-k",
        "5",
        "37",
        "sh",
        "-c",
    )
    assert args[11] == site_cron._TIMEOUT_SUPERVISOR
    assert 'setsid sh -lc "$command"' in args[11]
    assert 'kill -KILL -- "-$child"' in args[11]
    assert args[12:15] == ("wpfy-cron", job["command"], "2")
    assert args[15].startswith("__WPFY_CRON_TIMEOUT_")
    assert args[15].endswith("__")
    assert kwargs == {"timeout": 62}


def test_skip_runtime_never_attempts_compose_execution(tmp_wpfy_home, monkeypatch):
    site_cron = _reload_site_cron()
    _seed_site(tmp_wpfy_home)
    job = site_cron.add_job(DOMAIN, schedule="* * * * *", command="echo skipped", service="app")
    monkeypatch.setenv("WPFY_SKIP_RUNTIME", "1")
    monkeypatch.setattr(site_cron, "compose_command", lambda *args, **kwargs: pytest.fail("compose executed"))

    result = site_cron.run_job(DOMAIN, str(job["id"]))

    assert result.skipped is True
    assert result.outcome == "skipped"
    assert "WPFY_SKIP_RUNTIME" in result.message


def test_job_lock_blocks_overlap_and_closed_holder_is_stale_safe(tmp_wpfy_home, monkeypatch):
    site_cron = _reload_site_cron()
    _seed_site(tmp_wpfy_home)
    job = site_cron.add_job(DOMAIN, schedule="* * * * *", command="echo lock", service="app")
    monkeypatch.setattr(site_cron, "runtime_skip_requested", lambda: False)
    monkeypatch.setattr(site_cron, "docker_available", lambda: True)
    monkeypatch.setattr(
        site_cron,
        "compose_command",
        lambda domain, *args, **kwargs: subprocess.CompletedProcess(
            args,
            0,
            "app-container-id\n" if "ps" in args else "",
            "",
        ),
    )

    holder = site_cron._acquire_job_lock(DOMAIN, str(job["id"]))
    assert holder is not None
    overlap = site_cron.run_job(DOMAIN, str(job["id"]))
    assert overlap.skipped is True
    assert "already running" in overlap.message

    os.close(holder)  # A dead holder closes its descriptors; the kernel releases flock automatically.
    takeover = site_cron.run_job(DOMAIN, str(job["id"]))
    assert takeover.ran is True
    assert takeover.outcome == "ok"
    assert site_cron._lock_path(DOMAIN, str(job["id"])).is_file()


def test_host_backstop_timeout_is_reported_as_timeout(tmp_wpfy_home, monkeypatch):
    site_cron = _reload_site_cron()
    _seed_site(tmp_wpfy_home)
    job = site_cron.add_job(
        DOMAIN,
        schedule="* * * * *",
        command="sleep 60",
        service="app",
        timeout=7,
    )
    seen = []

    def timeout(domain, *args, **kwargs):
        seen.append((args, kwargs["timeout"]))
        if "ps" in args:
            return subprocess.CompletedProcess(args, 0, "app-container-id\n", "")
        raise subprocess.TimeoutExpired(args, kwargs["timeout"])

    monkeypatch.setattr(site_cron, "runtime_skip_requested", lambda: False)
    monkeypatch.setattr(site_cron, "docker_available", lambda: True)
    monkeypatch.setattr(site_cron, "compose_command", timeout)

    result = site_cron.run_job(DOMAIN, str(job["id"]))

    assert [value for _, value in seen] == [32]
    assert result.outcome == "timeout"
    assert result.exit_code == 124
    assert result.ran is True


def test_in_container_timeout_exit_124_is_reported_as_timeout(tmp_wpfy_home, monkeypatch):
    site_cron = _reload_site_cron()
    _seed_site(tmp_wpfy_home)
    job = site_cron.add_job(
        DOMAIN,
        schedule="* * * * *",
        command="sleep 60",
        service="app",
        timeout=7,
    )

    def compose(domain, *args, **kwargs):
        if "ps" in args:
            return subprocess.CompletedProcess(args, 0, "app-container-id\n", "")
        return subprocess.CompletedProcess(args, 124, "", f"Terminated\n{args[-1]}\n")

    monkeypatch.setattr(site_cron, "runtime_skip_requested", lambda: False)
    monkeypatch.setattr(site_cron, "docker_available", lambda: True)
    monkeypatch.setattr(site_cron, "compose_command", compose)

    result = site_cron.run_job(DOMAIN, str(job["id"]))

    assert result.outcome == "timeout"
    assert result.exit_code == 124
    assert result.ran is True
    assert result.message == "cron job exceeded 7 seconds"


def test_natural_exit_124_without_timeout_marker_is_failed(tmp_wpfy_home, monkeypatch):
    site_cron = _reload_site_cron()
    _seed_site(tmp_wpfy_home)
    job = site_cron.add_job(
        DOMAIN,
        schedule="* * * * *",
        command="exit 124",
        service="app",
        timeout=7,
    )

    def compose(domain, *args, **kwargs):
        if "ps" in args:
            return subprocess.CompletedProcess(args, 0, "app-container-id\n", "")
        return subprocess.CompletedProcess(args, 124, "", "application chose status 124")

    monkeypatch.setattr(site_cron, "runtime_skip_requested", lambda: False)
    monkeypatch.setattr(site_cron, "docker_available", lambda: True)
    monkeypatch.setattr(site_cron, "compose_command", compose)

    result = site_cron.run_job(DOMAIN, str(job["id"]))

    assert result.outcome == "failed"
    assert result.exit_code == 124
    assert result.message == "application chose status 124"


def test_runtime_down_skip_is_not_backfilled_on_the_next_tick(tmp_wpfy_home, monkeypatch):
    site_cron = _reload_site_cron()
    _seed_site(tmp_wpfy_home)
    site_cron.add_job(DOMAIN, schedule="* * * * *", command="echo once", service="app")
    calls = []

    def compose(domain, *args, **kwargs):
        calls.append(args)
        if len(calls) == 1:
            return subprocess.CompletedProcess(args, 1, "", "Error: service is not running")
        if "ps" in args:
            return subprocess.CompletedProcess(args, 0, "", "")
        return subprocess.CompletedProcess(args, 0, "", "")

    monkeypatch.setattr(site_cron, "list_sites", lambda: [{"domain": DOMAIN}])
    monkeypatch.setattr(site_cron, "runtime_skip_requested", lambda: False)
    monkeypatch.setattr(site_cron, "docker_available", lambda: True)
    monkeypatch.setattr(site_cron, "compose_command", compose)

    first = site_cron.run_due(datetime(2026, 7, 24, 10, 30))
    second = site_cron.run_due(datetime(2026, 7, 24, 10, 31))

    assert [job.outcome for job in first.jobs] == ["skipped"]
    assert [job.outcome for job in second.jobs] == ["ok"]
    assert len(calls) == 3


def test_job_output_cannot_masquerade_as_a_stopped_runtime(tmp_wpfy_home, monkeypatch):
    site_cron = _reload_site_cron()
    _seed_site(tmp_wpfy_home)
    job = site_cron.add_job(DOMAIN, schedule="* * * * *", command="exit 9", service="app")

    def compose(domain, *args, **kwargs):
        if "ps" in args:
            return subprocess.CompletedProcess(args, 0, "app-container-id\n", "")
        return subprocess.CompletedProcess(args, 9, "", "application dependency is not running")

    monkeypatch.setattr(site_cron, "runtime_skip_requested", lambda: False)
    monkeypatch.setattr(site_cron, "docker_available", lambda: True)
    monkeypatch.setattr(site_cron, "compose_command", compose)

    result = site_cron.run_job(DOMAIN, str(job["id"]))

    assert result.outcome == "failed"
    assert result.exit_code == 9
    assert result.ran is True
    assert result.skipped is False


def test_one_failed_job_does_not_abort_other_sites_in_the_tick(tmp_wpfy_home, monkeypatch):
    site_cron = _reload_site_cron()
    other = "other-cron.example.com"
    _seed_site(tmp_wpfy_home)
    _seed_site(tmp_wpfy_home, domain=other)
    site_cron.add_job(DOMAIN, schedule="* * * * *", command="exit 9", service="app")
    site_cron.add_job(other, schedule="* * * * *", command="echo healthy", service="app")

    def compose(domain, *args, **kwargs):
        if "ps" in args:
            return subprocess.CompletedProcess(args, 0, "app-container-id\n", "")
        return subprocess.CompletedProcess(args, 9 if domain == DOMAIN else 0, "", "failed")

    monkeypatch.setattr(site_cron, "list_sites", lambda: [{"domain": DOMAIN}, {"domain": other}])
    monkeypatch.setattr(site_cron, "runtime_skip_requested", lambda: False)
    monkeypatch.setattr(site_cron, "docker_available", lambda: True)
    monkeypatch.setattr(site_cron, "compose_command", compose)

    result = site_cron.run_due(datetime(2026, 7, 24, 10, 30))

    assert [(job.domain, job.outcome) for job in result.jobs] == [
        (DOMAIN, "failed"),
        (other, "ok"),
    ]
    assert result.exit_code == 1


def test_run_event_redacts_command_and_records_duration(tmp_wpfy_home, monkeypatch):
    site_cron = _reload_site_cron()
    _seed_site(tmp_wpfy_home)
    job = site_cron.add_job(
        DOMAIN,
        schedule="* * * * *",
        command="echo TOKEN=super-secret",
        service="app",
    )
    recorded = []
    monkeypatch.setattr(site_cron, "runtime_skip_requested", lambda: False)
    monkeypatch.setattr(site_cron, "docker_available", lambda: True)
    monkeypatch.setattr(
        site_cron,
        "compose_command",
        lambda domain, *args, **kwargs: subprocess.CompletedProcess(
            args,
            0,
            "app-container-id\n" if "ps" in args else "",
            "",
        ),
    )
    monkeypatch.setattr(site_cron.events, "record_event", lambda action, **kwargs: recorded.append((action, kwargs)))

    site_cron.run_job(DOMAIN, str(job["id"]))

    action, event = recorded[0]
    assert action == "site.cron.run"
    assert event["outcome"] == "ok"
    assert event["detail"]["command"] == "echo TOKEN=***REDACTED***"
    assert event["detail"]["duration_seconds"] >= 0
    assert event["detail"]["started_at"]


def test_daily_health_uses_shared_health_semantics(monkeypatch):
    from wpfy import cron
    from wpfy.site_runtime import HealthResult

    results = {
        "degraded.example.com": HealthResult(
            "degraded.example.com", True, True, False, False, "degraded", "runtime unavailable"
        ),
        "ready.example.com": HealthResult(
            "ready.example.com", True, True, True, True, "ready", "all services healthy"
        ),
        "unbootstrapped.example.com": HealthResult(
            "unbootstrapped.example.com", True, False, False, False, "needs-bootstrap", "files missing"
        ),
    }
    monkeypatch.setattr(cron, "list_sites", lambda: [{"domain": domain} for domain in results])
    monkeypatch.setattr(cron, "site_health", results.__getitem__)
    lines = []

    exit_code = cron._append_all_site_health(lines)

    assert exit_code == 1
    assert lines == [
        "degraded.example.com: health WARN runtime unavailable",
        "ready.example.com: health OK all services healthy",
        "unbootstrapped.example.com: health FAIL files missing",
    ]


def test_minute_interval_invokes_per_site_due_runner(monkeypatch):
    from wpfy import cron, metrics, site_cron

    seen = []
    due = site_cron.CronDueRun(
        datetime(2026, 7, 24, 10, 30),
        (site_cron.CronJobRun(DOMAIN, "job123", "ok", "done", 0.125, ran=True),),
    )
    monkeypatch.setattr(cron.site_cron, "run_due", lambda moment: seen.append(moment) or due)
    monkeypatch.setattr(cron.metrics, "sample_once", lambda: metrics.SampleRun(()))
    lines = []

    exit_code = cron._run_interval_tasks("minute", lines)

    assert exit_code == 0
    assert len(seen) == 1
    assert seen[0].second == 0
    assert lines == [f"{DOMAIN}: cron job123 OK duration=0.125s", "metrics sample: OK 0 scope(s)"]


def test_site_cron_cli_lifecycle_delegates_to_module(tmp_wpfy_home, monkeypatch, capsys):
    from wpfy import cli

    site_cron = _reload_site_cron()
    _seed_site(tmp_wpfy_home)
    monkeypatch.setattr(site_cron, "runtime_skip_requested", lambda: False)
    monkeypatch.setattr(site_cron, "docker_available", lambda: True)
    monkeypatch.setattr(
        site_cron,
        "compose_command",
        lambda *args, **kwargs: subprocess.CompletedProcess(args, 0, "", ""),
    )

    assert cli.run([
        "site", "cron", DOMAIN, "add",
        "--schedule", "*/5 * * * *",
        "--command", "echo cli",
        "--timeout", "19",
    ]) == 0
    job = site_cron.load_cron(DOMAIN)[0]
    assert cli.run(["site", "cron", DOMAIN, "disable", str(job["id"])]) == 0
    assert cli.run(["site", "cron", DOMAIN, "enable", str(job["id"])]) == 0
    assert cli.run(["site", "cron", DOMAIN, "list"]) == 0
    assert cli.run(["site", "cron", DOMAIN, "run", str(job["id"])]) == 0
    assert cli.run(["site", "cron", DOMAIN, "remove", str(job["id"])]) == 0

    output = capsys.readouterr().out
    assert "cron job added" in output
    assert "*/5 * * * *" in output
    assert "cron job removed" in output
    assert site_cron.load_cron(DOMAIN) == []
