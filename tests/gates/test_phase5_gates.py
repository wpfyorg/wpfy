"""OPUS-OWNED IMMUTABLE GATE TESTS — Phase 5a (metrics time-series sampler).

DO NOT EDIT, SKIP, XFAIL, PARAMETRIZE AWAY, OR DELETE ANYTHING IN THIS FILE.

These tests are the security and correctness contract for Phase 5a. They are
written by the orchestrator before implementation and are verified byte-identical
(SHA-256 baseline) as a precondition for accepting the phase. If you believe a
gate asserts the wrong thing, escalate with evidence — do not edit the gate.

This file is deliberately self-contained: it depends only on the stdlib and the
`wpfy` package, never on other test modules or shared fixtures.

What this phase can get wrong that nothing else catches:

    The sampler is the first module to put a *query language* between the panel
    and per-site data, and the first to run on the minute tick beside every
    site's WordPress cron. Three failure classes follow from that, and no
    existing test observes any of them:

    1. Scope is attacker-influenced text that reaches SQL. `?scope=` comes off
       the wire in Phase 5b. String interpolation, or `LIKE` instead of `=`,
       turns one site's dashboard into every site's dashboard.
    2. Per-site attribution is prefix matching over container names. Docker
       project names are domains with dots replaced by dashes, so
       `metrics-example` is a strict prefix of `metrics-example-org`. A prefix
       match silently bills one site's CPU to a different site's graph — wrong
       data that looks completely plausible.
    3. The sampler shares a process with the minute tick. An unhandled
       exception, a division by zero on two identical `/proc/stat` reads, or a
       `docker stats` invocation that streams forever does not merely lose a
       data point: it stops WordPress cron and per-site cron for every site on
       the box.

Invariants locked here:
  M1   A hostile `scope` neither damages the table nor returns another scope's
       rows. Includes `%` and `_`, which pass only if the query uses `=` and not
       `LIKE`.
  M2   Anti-vacuity for M1: a valid scope returns its own rows and only its own.
  M3   Container-name attribution is exact, not prefix-based: a domain whose
       project name is a strict prefix of another domain's must not absorb the
       longer site's samples.
  M4   Anti-vacuity for M3: both sites are actually sampled, under their domain
       names rather than their project names, from the container names wpfy
       really emits — `{project}-{service}` with no replica index, because every
       generated service sets an explicit `container_name`. A site with two
       containers has them summed.
  M5   A container belonging to no site is attributed to no site — both the
       shared edge proxy and an unrelated stack whose name does carry a replica
       index — and no scope outside {host} ∪ managed domains is ever written.
  M6   Memory is parsed at the right scale from both `docker stats` and
       `/proc/meminfo` — a 1000x unit error is the likeliest silent defect and
       is invisible until a graph is read.
  M7   Only read-only Docker verbs are invoked, and any `docker stats` carries
       `--no-stream`. Without it the call never returns and the minute tick
       hangs forever.
  M8   Sampling invokes no host-mutating command at all.
  M9   Sampling writes nothing under the site directories.
  M10  The database lives under the redirectable state dir, is not writable by
       group or other, and contains no site secret.
  M11  Two identical `/proc/stat` reads produce a finite in-range number rather
       than a crash or a NaN. This is the zero-delta division.
  M12  Docker being unavailable does not cost the host sample.
  M13  An invalid range is refused; every documented range is accepted.
  M14  A range actually bounds what is returned.
  M15  Retention prunes what is older and keeps what is not.
  M16  The minute tick records a sample, survives a sampler that raises, and
       says so in its log rather than swallowing the failure.
  M17  The daily tick prunes.
  M18  WAL is on and concurrent appends do not fail.

Contract pinned by these gates (the actor must match these names):
  * `wpfy.metrics.metrics_db_path() -> Path`   under `PATHS.state_dir`
  * `wpfy.metrics.sample_once()`               return type is the actor's choice
  * `wpfy.metrics.read_samples(scope, range_key)` -> sequence of samples, each
        exposing `timestamp` (int, unix seconds), `scope` (str, `"host"` or a
        domain), `cpu_percent`, `memory_used`, `memory_total`, `disk_used`,
        `disk_total`, `load1`. Raises `ValueError` on an unknown range.
  * `wpfy.metrics.prune(...)` -> int rows deleted, default retention
        `wpfy.metrics.RETENTION_DAYS`
  * `wpfy.metrics.RANGES`      == ("30m", "1h", "3h", "6h", "12h", "24h")
  * `wpfy.metrics.HOST_SCOPE`  == "host"
  * sqlite table `samples`, columns `timestamp, scope, cpu_percent,
        memory_used, memory_total, disk_used, disk_total, load1`
  * `wpfy.cron` calls `metrics.sample_once()` and `metrics.prune()` through the
        module object, so both stay monkeypatchable from the tick.

Two test hooks are pinned, following the existing `WPFY_TEST_*` convention:
  * `WPFY_TEST_PROC_DIR`  — directory holding `stat` and `meminfo`, read in
        place of `/proc`. Without it these gates could not run on a non-Linux
        host, and the zero-delta case (M11) would be unreachable.
  * per-site Docker stats are NOT hooked by an env var. These gates put a fake
        `docker` first on PATH which answers `stats` with JSON lines and `ps`
        with bare container names, and logs every invocation. That keeps M7 and
        M8 honest no matter how the module shells out.
"""

from __future__ import annotations

import json
import math
import os
import sqlite3
import threading
import time
from pathlib import Path

import pytest

SEEDED_DOMAIN = "metrics.example"
# Chosen so `metrics-example` is a strict prefix of `metrics-example-org`.
PREFIX_DOMAIN = "metrics.example.org"
SECRET_MARKER = "PH5-DB-SECRET-4c81ea"
ROOT_SECRET_MARKER = "PH5-ROOT-SECRET-7fd230"

EXPECTED_RANGES = ("30m", "1h", "3h", "6h", "12h", "24h")

# Distinctive CPU values so attribution can be traced by value alone.
SEEDED_CPU = 5.0
# The prefix-colliding site has two containers, so its total also proves that a
# site's containers are summed rather than last-one-wins.
PREFIX_APP_CPU = 70.0
PREFIX_WEB_CPU = 7.5
PREFIX_CPU = PREFIX_APP_CPU + PREFIX_WEB_CPU
PREFIX_MEMORY_USED = (400 + 100) * 1024**2
EDGE_CPU = 3.0
# A container belonging to no wpfy site, which does carry a replica index.
FOREIGN_CPU = 12.0
# A value no sampler would produce, used to tag rows this file inserts.
OLD_ROW_CPU = 42.0
MID_ROW_CPU = 43.0

_GATE_ENV = (
    "WPFY_INSTALL_ROOT",
    "WPFY_CONFIG_DIR",
    "WPFY_STATE_DIR",
    "WPFY_LOG_DIR",
    "WPFY_SKIP_RUNTIME",
    "WPFY_SKIP_WORDPRESS_DOWNLOAD",
    "WPFY_SKIP_CHOWN",
    "WPFY_TEST_PROC_DIR",
    "WPFY_GATE_DOCKER_LOG",
    "WPFY_GATE_DOCKER_STATS",
    "WPFY_GATE_DOCKER_NAMES",
    "WPFY_GATE_FORBIDDEN_LOG",
    "PATH",
)

_PATH_FIELDS = ("install_root", "config_dir", "state_dir", "log_dir")

# `%` and `_` are the interesting ones: they are inert against `WHERE scope = ?`
# and match everything against `WHERE scope LIKE ?`.
HOSTILE_SCOPES = (
    "host' OR 1=1 --",
    "host'; DROP TABLE samples;--",
    'host" OR "1"="1',
    "host\nDROP TABLE samples;",
    "host\x00",
    "../../etc/passwd",
    "%",
    "_ost",
    "metrics.example' UNION SELECT * FROM samples --",
)

_FAKE_DOCKER = """#!/bin/sh
printf '%s\\n' "$*" >> "$WPFY_GATE_DOCKER_LOG"
case "$1" in
  stats)
    if [ -f "$WPFY_GATE_DOCKER_STATS" ]; then cat "$WPFY_GATE_DOCKER_STATS"; fi
    ;;
  ps)
    if [ -f "$WPFY_GATE_DOCKER_NAMES" ]; then cat "$WPFY_GATE_DOCKER_NAMES"; fi
    ;;
  version|info)
    printf 'wpfy-gate-fake-docker\\n'
    ;;
esac
exit 0
"""

_FAKE_FORBIDDEN = """#!/bin/sh
printf '%s %s\\n' "$(basename "$0")" "$*" >> "$WPFY_GATE_FORBIDDEN_LOG"
exit 0
"""

# Commands that would mutate the host. Sampling must invoke none of them.
FORBIDDEN_COMMANDS = ("systemctl", "service", "apt", "apt-get", "reboot", "shutdown")

# Read-only Docker verbs. Anything else is a mutation or an unbounded call.
ALLOWED_DOCKER_VERBS = frozenset({"stats", "ps", "version", "info"})

_PROC_STAT = """cpu  100 10 50 840 0 0 0 0 0 0
cpu0 50 5 25 420 0 0 0 0 0 0
cpu1 50 5 25 420 0 0 0 0 0 0
intr 12345
ctxt 54321
btime 1700000000
processes 999
procs_running 1
procs_blocked 0
"""

# MemTotal 2048000 kB is 2_097_152_000 bytes. An implementation that treats the
# kB column as bytes lands near 2.0e6 and fails M6.
_PROC_MEMINFO = """MemTotal:        2048000 kB
MemFree:          256000 kB
MemAvailable:     512000 kB
Buffers:           64000 kB
Cached:           256000 kB
SwapTotal:             0 kB
SwapFree:              0 kB
"""


def _docker_stats_line(name: str, cpu: float, mem_used: str, mem_total: str) -> str:
    return json.dumps({
        "BlockIO": "0B / 0B",
        "CPUPerc": f"{cpu:.2f}%",
        "Container": name[:12],
        "ID": name[:12],
        "MemPerc": "1.00%",
        "MemUsage": f"{mem_used} / {mem_total}",
        "Name": name,
        "NetIO": "1.2kB / 0B",
        "PIDs": "5",
    })


# Real wpfy container names. Every generated service sets an explicit
# `container_name: {project}-{service}` — web and app (site_layout.py:172,266),
# db and redis (303,339), wpcli (380), sftp (site_definition.py:256), adminer
# (226) — which overrides docker-compose's default naming, so a wpfy container
# name carries NO replica index.
#
# An earlier revision of this fixture used `{project}-{service}-{N}`, the
# compose default that wpfy never emits. Verified against live containers on the
# development host, whose real names are `docker-proof-example-com-web`,
# `-app`, `-db` and `cron-proof-local-app`. A parser keyed on the numeric suffix
# discards every real container: `docker stats` runs, parses, and throws the
# result away, leaving per-site metrics permanently empty while the host scope
# keeps working and all 36 of these gates pass. The fixture is now the naming
# production actually uses, so that class of parser can no longer pass.
#
# `unrelated-stack-db-1` is the counterpart: a foreign container that does carry
# an index. It must be attributed to no site and must not crash the parser.
DOCKER_CONTAINERS = (
    (f"{SEEDED_DOMAIN.replace('.', '-')}-app", SEEDED_CPU, "1GiB", "2GiB"),
    (f"{PREFIX_DOMAIN.replace('.', '-')}-app", PREFIX_APP_CPU, "400MiB", "1GiB"),
    (f"{PREFIX_DOMAIN.replace('.', '-')}-web", PREFIX_WEB_CPU, "100MiB", "1GiB"),
    ("wpfy-traefik", EDGE_CPU, "64MiB", "2GiB"),
    ("unrelated-stack-db-1", FOREIGN_CPU, "128MiB", "256MiB"),
)


class GateHome:
    """Handles for the isolated wpfy home a gate runs against."""

    def __init__(self, paths, root: Path):
        self.paths = paths
        self.root = root
        self.docker_log = root / "docker-invocations.log"
        self.forbidden_log = root / "forbidden-invocations.log"
        self.bin_dir = root / "bin"

    def docker_invocations(self) -> list[str]:
        if not self.docker_log.exists():
            return []
        return [line for line in self.docker_log.read_text(encoding="utf-8").splitlines() if line.strip()]

    def forbidden_invocations(self) -> list[str]:
        if not self.forbidden_log.exists():
            return []
        return [line for line in self.forbidden_log.read_text(encoding="utf-8").splitlines() if line.strip()]

    def hide_docker(self) -> None:
        """Remove the fake docker so `docker` is absent from PATH entirely."""
        (self.bin_dir / "docker").unlink()


def _write_executable(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")
    path.chmod(0o755)


def _seed_site(paths, domain: str) -> Path:
    site = Path(paths.sites_dir) / domain
    (site / "nginx" / "extra").mkdir(parents=True, exist_ok=True)
    (site / "php").mkdir(parents=True, exist_ok=True)
    (site / "app").mkdir(parents=True, exist_ok=True)
    (site / ".env").write_text(
        f"DOMAIN={domain}\n"
        "SITE_FLAVOR=wp\n"
        f"COMPOSE_PROJECT_NAME={domain.replace('.', '-')}\n"
        "APP_ROOT=/var/www/html\n"
        "PHP_VERSION=8.4\n"
        "SITE_UID=1700\n"
        "LETSENCRYPT_MODE=disabled\n"
        "PAGE_CACHE=none\n"
        "DB_NAME=metricsdb\n"
        "DB_USER=metricsdb\n"
        f"DB_PASSWORD={SECRET_MARKER}\n"
        f"MARIADB_PASSWORD={SECRET_MARKER}\n"
        f"DB_ROOT_PASSWORD={ROOT_SECRET_MARKER}\n"
        f"MARIADB_ROOT_PASSWORD={ROOT_SECRET_MARKER}\n",
        encoding="utf-8",
    )
    (site / "compose.yaml").write_text("services: {}\n", encoding="utf-8")
    (site / "nginx" / "default.conf").write_text("server {\n    listen 8080;\n}\n", encoding="utf-8")
    (site / "nginx" / "extra" / "custom.conf").write_text("", encoding="utf-8")
    return site


@pytest.fixture
def gate_home(tmp_path):
    """An isolated, offline wpfy home with a fake Docker and a fake /proc.

    Paths are redirected by mutating the frozen `settings.PATHS` singleton in
    place. `importlib.reload` is deliberately avoided: it reuses a module's
    __dict__, so symbols captured at import time by other test modules keep
    pointing at the old class while the module starts producing the new one,
    silently breaking unrelated tests with no possible teardown.
    """
    import wpfy.registry
    import wpfy.settings
    import wpfy.site_runtime

    paths = wpfy.settings.PATHS
    previous_env = {name: os.environ.get(name) for name in _GATE_ENV}
    previous_paths = {field: getattr(paths, field) for field in _PATH_FIELDS}
    previous_registry = wpfy.registry._REGISTRY

    home = GateHome(paths, tmp_path)
    home.bin_dir.mkdir(parents=True, exist_ok=True)
    proc_dir = tmp_path / "proc"
    proc_dir.mkdir(parents=True, exist_ok=True)
    (proc_dir / "stat").write_text(_PROC_STAT, encoding="utf-8")
    (proc_dir / "meminfo").write_text(_PROC_MEMINFO, encoding="utf-8")

    stats_file = tmp_path / "docker-stats.json"
    names_file = tmp_path / "docker-names.txt"
    stats_file.write_text(
        "".join(f"{_docker_stats_line(*container)}\n" for container in DOCKER_CONTAINERS),
        encoding="utf-8",
    )
    names_file.write_text(
        "".join(f"{container[0]}\n" for container in DOCKER_CONTAINERS),
        encoding="utf-8",
    )

    os.environ.update({
        "WPFY_INSTALL_ROOT": str(tmp_path / "install"),
        "WPFY_CONFIG_DIR": str(tmp_path / "config"),
        "WPFY_STATE_DIR": str(tmp_path / "state"),
        "WPFY_LOG_DIR": str(tmp_path / "log"),
        "WPFY_SKIP_RUNTIME": "1",
        "WPFY_SKIP_WORDPRESS_DOWNLOAD": "1",
        "WPFY_SKIP_CHOWN": "1",
        "WPFY_TEST_PROC_DIR": str(proc_dir),
        "WPFY_GATE_DOCKER_LOG": str(home.docker_log),
        "WPFY_GATE_DOCKER_STATS": str(stats_file),
        "WPFY_GATE_DOCKER_NAMES": str(names_file),
        "WPFY_GATE_FORBIDDEN_LOG": str(home.forbidden_log),
        "PATH": f"{home.bin_dir}{os.pathsep}{os.environ.get('PATH', '')}",
    })
    for field in _PATH_FIELDS:
        object.__setattr__(paths, field, os.environ[f"WPFY_{field.upper()}"])
    Path(paths.state_dir).mkdir(parents=True, exist_ok=True)
    Path(paths.log_dir).mkdir(parents=True, exist_ok=True)

    _write_executable(home.bin_dir / "docker", _FAKE_DOCKER)
    for command in FORBIDDEN_COMMANDS:
        _write_executable(home.bin_dir / command, _FAKE_FORBIDDEN)

    wpfy.registry._REGISTRY = None
    wpfy.site_runtime.docker_available.cache_clear()

    _seed_site(paths, SEEDED_DOMAIN)
    _seed_site(paths, PREFIX_DOMAIN)

    try:
        yield home
    finally:
        for field, value in previous_paths.items():
            object.__setattr__(paths, field, value)
        wpfy.registry._REGISTRY = previous_registry
        wpfy.site_runtime.docker_available.cache_clear()
        for name, value in previous_env.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value


def _metrics():
    import wpfy.metrics as metrics

    return metrics


def _rows(home) -> list[tuple]:
    connection = sqlite3.connect(_metrics().metrics_db_path())
    try:
        return connection.execute(
            "SELECT timestamp, scope, cpu_percent, memory_used, memory_total, "
            "disk_used, disk_total, load1 FROM samples"
        ).fetchall()
    finally:
        connection.close()


def _insert_row(home, *, scope: str, timestamp: int, cpu: float) -> None:
    connection = sqlite3.connect(_metrics().metrics_db_path())
    try:
        connection.execute(
            "INSERT INTO samples (timestamp, scope, cpu_percent, memory_used, "
            "memory_total, disk_used, disk_total, load1) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (timestamp, scope, cpu, 1024, 2048, 4096, 8192, 0.5),
        )
        connection.commit()
    finally:
        connection.close()


def _cpu_values(samples) -> list[float]:
    return [float(sample.cpu_percent) for sample in samples]


def _scopes_recorded(home) -> set[str]:
    return {row[1] for row in _rows(home)}


def _samples_for(scope: str, range_key: str = "24h"):
    return list(_metrics().read_samples(scope, range_key))


def test_gate_range_vocabulary_is_exactly_as_documented(gate_home):
    """The panel builds its range selector from this tuple; it is a contract."""
    metrics = _metrics()
    assert tuple(metrics.RANGES) == EXPECTED_RANGES
    assert metrics.HOST_SCOPE == "host"


def test_gate_database_lives_under_the_redirectable_state_dir(gate_home):
    """A hardcoded /var/lib path would write to the real system during tests."""
    path = Path(_metrics().metrics_db_path())
    state_dir = Path(gate_home.paths.state_dir).resolve()
    assert state_dir in path.resolve().parents, (
        f"the metrics database at {path} is not under the state dir {state_dir}; "
        f"a path that ignores WPFY_STATE_DIR writes to the real host from tests"
    )


@pytest.mark.parametrize("scope", HOSTILE_SCOPES)
def test_gate_hostile_scope_neither_damages_the_table_nor_leaks_rows(gate_home, scope):
    """`scope` arrives from a query string in Phase 5b. It must be a bound parameter.

    Two failures are checked at once. The table must survive — a dropped or
    truncated `samples` means interpolation reached SQL. And the rows returned,
    if any, must all carry the scope that was asked for: `%` and `_` return
    everything under `LIKE` and nothing under `=`.
    """
    metrics = _metrics()
    metrics.sample_once()
    before = _rows(gate_home)
    assert before, "the sampler recorded nothing, so this gate could not detect damage"

    try:
        returned = list(metrics.read_samples(scope, "24h"))
    except ValueError:
        returned = []

    after = _rows(gate_home)
    assert len(after) == len(before), (
        f"the row count changed from {len(before)} to {len(after)} after reading "
        f"scope {scope!r}; the scope reached SQL as text"
    )
    leaked = [sample.scope for sample in returned if sample.scope != scope]
    assert not leaked, (
        f"reading scope {scope!r} returned rows belonging to {sorted(set(leaked))}; "
        f"a wildcard or injected predicate matched other scopes"
    )


def test_gate_valid_scope_returns_only_its_own_rows(gate_home):
    """Anti-vacuity for the hostile-scope gate: refusing everything is not a pass."""
    metrics = _metrics()
    metrics.sample_once()

    host_samples = _samples_for(metrics.HOST_SCOPE)
    assert host_samples, "no host sample was recorded, so scope filtering is untested"
    assert {sample.scope for sample in host_samples} == {metrics.HOST_SCOPE}


def test_gate_site_attribution_is_exact_not_prefix_matched(gate_home):
    """`metrics-example` is a strict prefix of `metrics-example-org`.

    Container names are the project name plus a service suffix, so a prefix or
    `startswith` match hands the longer site's CPU to the shorter site. The
    resulting graph is wrong and entirely plausible-looking, which is why this
    is a gate and not a unit test.
    """
    _metrics().sample_once()

    seeded = _cpu_values(_samples_for(SEEDED_DOMAIN))
    assert seeded, f"{SEEDED_DOMAIN} was not sampled at all"
    assert PREFIX_CPU not in seeded, (
        f"{SEEDED_DOMAIN} was credited with {PREFIX_CPU}%, which belongs to "
        f"{PREFIX_DOMAIN}; container matching is prefix-based"
    )
    assert max(seeded) < PREFIX_CPU, (
        f"{SEEDED_DOMAIN} reports {max(seeded)}% where its own container used "
        f"{SEEDED_CPU}%; another site's usage was folded in"
    )


def test_gate_both_sites_are_sampled_under_their_domain_names(gate_home):
    """Anti-vacuity for exact attribution, and a scope-naming contract.

    Recording the project name instead of the domain would satisfy the gate
    above while making every Phase 5b lookup silently return nothing.

    This is also the gate that fails if the parser only recognises the compose
    default `{project}-{service}-{N}`: none of the fixture's wpfy containers
    carry an index, because none of wpfy's generated services do.
    """
    _metrics().sample_once()

    assert _samples_for(SEEDED_DOMAIN), (
        f"{SEEDED_DOMAIN} has no samples; its container is named "
        f"`{SEEDED_DOMAIN.replace('.', '-')}-app` from an explicit "
        f"`container_name`, with no replica index"
    )
    prefix = _samples_for(PREFIX_DOMAIN)
    assert prefix, f"{PREFIX_DOMAIN} has no samples"
    prefix_cpu = _cpu_values(prefix)
    assert any(abs(value - PREFIX_CPU) < 0.6 for value in prefix_cpu), (
        f"{PREFIX_DOMAIN} reports {prefix_cpu} but its two containers used "
        f"{PREFIX_APP_CPU}% and {PREFIX_WEB_CPU}%, totalling {PREFIX_CPU}%"
    )
    assert any(abs(sample.memory_used - PREFIX_MEMORY_USED) < 1024**2 for sample in prefix), (
        f"{PREFIX_DOMAIN} reports memory {[sample.memory_used for sample in prefix]} "
        f"but its two containers used 400MiB and 100MiB, totalling {PREFIX_MEMORY_USED}"
    )


def test_gate_foreign_containers_are_attributed_to_no_site(gate_home):
    """The edge proxy and unrelated stacks belong to no site and must not become one.

    `unrelated-stack-db-1` additionally carries a replica index, so a parser that
    strips a numeric suffix and then matches loosely gets caught here rather than
    quietly inventing a scope.
    """
    metrics = _metrics()
    metrics.sample_once()

    permitted = {metrics.HOST_SCOPE, SEEDED_DOMAIN, PREFIX_DOMAIN}
    unexpected = _scopes_recorded(gate_home) - permitted
    assert not unexpected, (
        f"scopes {sorted(unexpected)} were written; only the host and managed "
        f"domains are valid scopes, and neither `wpfy-traefik` nor "
        f"`unrelated-stack-db-1` is either"
    )
    for domain in (SEEDED_DOMAIN, PREFIX_DOMAIN):
        billed = _cpu_values(_samples_for(domain))
        assert EDGE_CPU not in billed, f"the edge proxy's {EDGE_CPU}% was billed to {domain}"
        assert FOREIGN_CPU not in billed, (
            f"an unrelated stack's {FOREIGN_CPU}% was billed to {domain}"
        )


def test_gate_memory_is_parsed_at_the_right_scale(gate_home):
    """A 1000x unit error is silent until somebody reads a graph.

    `docker stats` reports `1GiB / 2GiB` and `/proc/meminfo` reports kB. Both
    are routinely mistaken for bytes. The bounds below accept either binary or
    decimal interpretation and reject only an error of scale.
    """
    metrics = _metrics()
    metrics.sample_once()

    site = _samples_for(SEEDED_DOMAIN)[0]
    assert 1.0e9 <= site.memory_used <= 1.15e9, (
        f"a container using 1GiB was recorded as {site.memory_used} bytes"
    )
    assert 2.0e9 <= site.memory_total <= 2.3e9, (
        f"a 2GiB limit was recorded as {site.memory_total} bytes"
    )

    host = _samples_for(metrics.HOST_SCOPE)[0]
    assert 2.0e9 <= host.memory_total <= 2.2e9, (
        f"MemTotal of 2048000 kB was recorded as {host.memory_total} bytes"
    )
    assert 0 < host.memory_used < host.memory_total, (
        f"host memory_used {host.memory_used} is not inside (0, {host.memory_total})"
    )


def test_gate_only_read_only_docker_verbs_and_never_a_streaming_stats(gate_home):
    """`docker stats` without `--no-stream` never returns.

    The sampler runs on the minute tick. A call that blocks forever does not
    lose a data point, it stops WordPress cron and per-site cron for every site
    on the machine until someone notices.
    """
    _metrics().sample_once()

    invocations = gate_home.docker_invocations()
    assert invocations, "the sampler never invoked docker, so per-site stats are untested"
    for line in invocations:
        verb = line.split()[0] if line.split() else ""
        assert verb in ALLOWED_DOCKER_VERBS, (
            f"docker was invoked with the verb {verb!r}: {line!r}; sampling is "
            f"read-only and may use only {sorted(ALLOWED_DOCKER_VERBS)}"
        )
        if verb == "stats":
            assert "--no-stream" in line.split(), (
                f"`docker stats` was invoked without --no-stream: {line!r}; this "
                f"call never returns and hangs the cron tick"
            )


def test_gate_sampling_invokes_no_host_mutating_command(gate_home):
    """Read-only by construction is a claim; this is the check."""
    _metrics().sample_once()

    invocations = gate_home.forbidden_invocations()
    assert not invocations, (
        f"sampling invoked host-mutating commands: {invocations}; wpfy never "
        f"mutates the host, and a metrics sampler has no reason to try"
    )


def test_gate_sampling_writes_nothing_under_the_site_directories(gate_home):
    """Sampling observes sites. It does not touch them."""
    sites_dir = Path(gate_home.paths.sites_dir)

    def snapshot() -> dict[str, tuple[int, int]]:
        return {
            str(path.relative_to(sites_dir)): (path.stat().st_size, path.stat().st_mtime_ns)
            for path in sorted(sites_dir.rglob("*"))
            if path.is_file()
        }

    before = snapshot()
    assert before, "no site files were seeded, so this gate would be vacuous"
    _metrics().sample_once()
    after = snapshot()

    assert after == before, (
        "sampling changed files under the site directories: "
        f"{sorted(set(after) ^ set(before)) or [key for key in before if before[key] != after.get(key)]}"
    )


def test_gate_database_is_not_group_or_world_writable(gate_home):
    """A tamperable metrics store lets any local user forge a site's history."""
    _metrics().sample_once()
    path = Path(_metrics().metrics_db_path())
    mode = path.stat().st_mode & 0o777
    assert not mode & 0o022, f"{path} has mode {mode:04o}; group/other must not be able to write"


def test_gate_no_site_secret_reaches_the_metrics_store(gate_home):
    """Metrics are secret-free by construction. Construction is what this checks."""
    _metrics().sample_once()
    path = Path(_metrics().metrics_db_path())

    for candidate in (path, Path(f"{path}-wal"), Path(f"{path}-shm")):
        if not candidate.exists():
            continue
        blob = candidate.read_bytes()
        for marker in (SECRET_MARKER, ROOT_SECRET_MARKER):
            assert marker.encode() not in blob, f"{marker} appears in {candidate.name}"


def test_gate_identical_proc_reads_do_not_divide_by_zero(gate_home):
    """Two reads of a static /proc/stat give a zero total delta.

    On an idle machine with a coarse clock this happens for real. A naive
    `busy_delta / total_delta` raises ZeroDivisionError inside the minute tick.
    The fixture makes the case deterministic rather than occasional.
    """
    metrics = _metrics()
    metrics.sample_once()

    host = _samples_for(metrics.HOST_SCOPE)
    assert host, "no host sample recorded"
    for sample in host:
        assert math.isfinite(sample.cpu_percent), f"cpu_percent is {sample.cpu_percent}"
        assert 0.0 <= sample.cpu_percent <= 100.0, f"cpu_percent {sample.cpu_percent} out of range"
        assert sample.load1 >= 0.0, f"load1 {sample.load1} is negative"
        assert 0 < sample.disk_used <= sample.disk_total, (
            f"disk_used {sample.disk_used} is not inside (0, {sample.disk_total}]"
        )


def test_gate_missing_docker_does_not_cost_the_host_sample(gate_home):
    """Host history must not depend on the container runtime being up.

    Losing per-site rows when Docker is down is correct. Losing the host's CPU,
    memory, disk and load at the same moment is exactly when an operator needs
    them most.
    """
    metrics = _metrics()
    import wpfy.site_runtime

    gate_home.hide_docker()
    wpfy.site_runtime.docker_available.cache_clear()

    metrics.sample_once()

    host = _samples_for(metrics.HOST_SCOPE)
    assert host, "no host sample was recorded while docker was unavailable"
    assert not gate_home.docker_invocations(), "docker was invoked despite being absent"


def test_gate_an_unknown_range_is_refused(gate_home):
    metrics = _metrics()
    metrics.sample_once()
    for bad in ("99y", "30", "", "1h; DROP TABLE samples", "-1h"):
        with pytest.raises(ValueError):
            metrics.read_samples(metrics.HOST_SCOPE, bad)
    assert _rows(gate_home), "the samples table did not survive the refused ranges"


@pytest.mark.parametrize("range_key", EXPECTED_RANGES)
def test_gate_every_documented_range_is_accepted(gate_home, range_key):
    """Anti-vacuity for range refusal: rejecting all ranges is not a pass."""
    metrics = _metrics()
    metrics.sample_once()
    assert list(metrics.read_samples(metrics.HOST_SCOPE, range_key)), (
        f"range {range_key!r} returned nothing for a sample taken just now"
    )


def test_gate_a_range_actually_bounds_what_is_returned(gate_home):
    """An implementation that ignores the range ships 20k points to the browser."""
    metrics = _metrics()
    metrics.sample_once()
    now = int(time.time())
    _insert_row(gate_home, scope=metrics.HOST_SCOPE, timestamp=now - 2 * 3600, cpu=OLD_ROW_CPU)
    _insert_row(gate_home, scope=metrics.HOST_SCOPE, timestamp=now - 10 * 60, cpu=MID_ROW_CPU)

    narrow = _cpu_values(_samples_for(metrics.HOST_SCOPE, "30m"))
    wide = _cpu_values(_samples_for(metrics.HOST_SCOPE, "24h"))

    assert MID_ROW_CPU in narrow, "a 10-minute-old row is missing from the 30m range"
    assert OLD_ROW_CPU not in narrow, "a 2-hour-old row was returned inside the 30m range"
    assert OLD_ROW_CPU in wide, "a 2-hour-old row is missing from the 24h range"


def test_gate_retention_prunes_what_is_older_and_keeps_what_is_not(gate_home):
    """Bounded growth is the whole reason retention exists — in both directions."""
    metrics = _metrics()
    metrics.sample_once()
    now = int(time.time())
    stale = now - (metrics.RETENTION_DAYS + 1) * 86400
    _insert_row(gate_home, scope=metrics.HOST_SCOPE, timestamp=stale, cpu=OLD_ROW_CPU)
    _insert_row(gate_home, scope=SEEDED_DOMAIN, timestamp=stale, cpu=OLD_ROW_CPU)
    _insert_row(gate_home, scope=metrics.HOST_SCOPE, timestamp=now - 600, cpu=MID_ROW_CPU)

    deleted = metrics.prune()

    assert deleted >= 2, f"prune reported {deleted} rows deleted; two were stale"
    remaining = {(row[1], row[0]) for row in _rows(gate_home)}
    assert not [row for row in remaining if row[1] <= stale], "stale rows survived prune"
    assert MID_ROW_CPU in _cpu_values(_samples_for(metrics.HOST_SCOPE, "1h")), (
        "prune deleted a row that was inside the retention window"
    )


def test_gate_minute_tick_records_a_sample(gate_home):
    """Wiring is the point: an unwired sampler collects nothing forever."""
    import wpfy.cron

    before = len(_rows(gate_home)) if Path(_metrics().metrics_db_path()).exists() else 0
    run = wpfy.cron.run_interval("minute")

    assert len(_rows(gate_home)) > before, (
        f"the minute tick recorded no sample; lines were {run.lines}"
    )


def test_gate_minute_tick_survives_a_sampler_that_raises_and_says_so(gate_home, monkeypatch):
    """A new failure domain must not take the existing tick down with it.

    Swallowing the failure silently is the other half of the trap: a dashboard
    that has been empty for a month with nothing in the log is indistinguishable
    from a dashboard nobody looked at.
    """
    import wpfy.cron
    import wpfy.metrics

    def explode():
        raise RuntimeError("gate-injected sampler failure")

    monkeypatch.setattr(wpfy.metrics, "sample_once", explode)

    run = wpfy.cron.run_interval("minute")

    assert "cron minute: done" in run.lines, (
        f"the minute tick did not complete when sampling raised: {run.lines}"
    )
    assert any("metric" in line.lower() for line in run.lines), (
        f"the sampler failure is absent from the tick log: {run.lines}"
    )


def test_gate_daily_tick_prunes(gate_home):
    import wpfy.cron

    metrics = _metrics()
    metrics.sample_once()
    stale = int(time.time()) - (metrics.RETENTION_DAYS + 1) * 86400
    _insert_row(gate_home, scope=metrics.HOST_SCOPE, timestamp=stale, cpu=OLD_ROW_CPU)

    wpfy.cron.run_interval("daily")

    assert OLD_ROW_CPU not in [row[2] for row in _rows(gate_home)], (
        "the daily tick left a row older than retention in place"
    )


def test_gate_wal_is_enabled_and_concurrent_appends_do_not_fail(gate_home):
    """Two writers meet here: the cron tick and a panel read/prune.

    Under the default rollback journal one of them gets `database is locked`,
    which surfaces as a crashed cron tick.
    """
    metrics = _metrics()
    metrics.sample_once()

    connection = sqlite3.connect(metrics.metrics_db_path())
    try:
        mode = connection.execute("PRAGMA journal_mode").fetchone()[0]
    finally:
        connection.close()
    assert str(mode).lower() == "wal", f"journal_mode is {mode!r}, not wal"

    errors: list[BaseException] = []

    def sample():
        try:
            metrics.sample_once()
        except BaseException as exc:  # noqa: BLE001 - the gate reports whatever escaped
            errors.append(exc)

    threads = [threading.Thread(target=sample) for _ in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=60)

    assert not errors, f"concurrent sampling raised: {errors!r}"
