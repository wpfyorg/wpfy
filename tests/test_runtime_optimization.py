from __future__ import annotations

import importlib
import hashlib
import io
import tarfile
from collections import Counter
from pathlib import Path


class Proc:
    def __init__(self, returncode: int = 0, stdout: str = "", stderr: str = "") -> None:
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def _ready_site(layout, domain: str, flavor: str, *, mysql: bool, redis: bool) -> None:
    spec = layout.SiteSpec(domain=domain, flavor=flavor, use_mysql=mysql, use_redis=redis)
    layout.ensure_site_scaffold(spec)
    layout.healthcheck_path(domain).write_text(f"wpfy-ok {domain}\n", encoding="utf-8")
    layout.app_dir(domain).joinpath("index.php").write_text("<?php\n", encoding="utf-8")
    if flavor in layout.WORDPRESS_FLAVORS:
        layout.app_dir(domain).joinpath("wp-config.php").write_text("<?php\n", encoding="utf-8")


def test_docker_available_probes_once_per_process(monkeypatch):
    import wpfy.site_runtime as runtime

    importlib.reload(runtime)
    calls = []
    monkeypatch.setattr(runtime.shutil, "which", lambda command: f"/usr/bin/{command}")
    monkeypatch.setattr(runtime.subprocess, "run", lambda *args, **kwargs: calls.append(args) or Proc())

    runtime.docker_available.cache_clear()
    assert runtime.docker_available() is True
    assert runtime.docker_available() is True
    assert len(calls) == 1
    runtime.docker_available.cache_clear()


def test_site_health_queries_each_required_service_once(tmp_wpfy_home, monkeypatch):
    import wpfy.site_layout as layout
    import wpfy.site_runtime as runtime

    importlib.reload(layout)
    importlib.reload(runtime)
    domain = "health.example.com"
    _ready_site(layout, domain, "wpredis", mysql=True, redis=True)
    calls = []

    monkeypatch.setattr(runtime, "docker_available", lambda: True)
    monkeypatch.setattr(
        runtime,
        "_compose_service_ids",
        lambda domain_arg, service: calls.append(service) or [f"{service}-id"],
    )
    monkeypatch.setattr(runtime, "_container_health", lambda container_id: "healthy")
    monkeypatch.setattr(runtime, "_compose_exec", lambda *args: Proc(stdout=f"wpfy-ok {domain}"))

    result = runtime.site_health(domain)

    assert result.runtime_ready is True
    assert Counter(calls) == Counter({"web": 1, "app": 1, "db": 1, "redis": 1})


def test_site_health_skips_services_not_used_by_flavor(tmp_wpfy_home, monkeypatch):
    import wpfy.site_layout as layout
    import wpfy.site_runtime as runtime

    importlib.reload(layout)
    importlib.reload(runtime)
    domain = "static.example.com"
    _ready_site(layout, domain, "html", mysql=False, redis=False)
    calls = []

    monkeypatch.setattr(runtime, "docker_available", lambda: True)
    monkeypatch.setattr(
        runtime,
        "_compose_service_ids",
        lambda domain_arg, service: calls.append(service) or [f"{service}-id"],
    )
    monkeypatch.setattr(runtime, "_container_health", lambda container_id: "healthy")
    monkeypatch.setattr(runtime, "_compose_exec", lambda *args: Proc(stdout=f"wpfy-ok {domain}"))

    result = runtime.site_health(domain)

    assert result.runtime_ready is True
    assert Counter(calls) == Counter({"web": 1, "app": 1})


def test_backup_streams_database_dump_to_archive(tmp_wpfy_home, monkeypatch):
    import wpfy.site_layout as layout

    importlib.reload(layout)
    domain = "stream-backup.example.com"
    _ready_site(layout, domain, "wp", mysql=True, redis=False)

    def fake_run(args, **kwargs):
        if "mariadb-dump" in args[-1]:
            assert "stdout" in kwargs
            assert "capture_output" not in kwargs
            assert kwargs["stdout"].name.endswith(".sql.part")
            assert Path(kwargs["stdout"].name).stat().st_mode & 0o777 == 0o600
            kwargs["stdout"].write("CREATE TABLE streamed (id INT);\n")
            return Proc()
        return Proc()

    monkeypatch.setattr(layout, "docker_available", lambda: True)
    monkeypatch.setattr(layout, "runtime_skip_requested", lambda: False)
    monkeypatch.setattr(layout.subprocess, "run", fake_run)

    result = layout.backup_site(domain)

    assert result.exit_code == 0
    archive_path = Path(result.message.removeprefix("backup created: "))
    with tarfile.open(archive_path, "r:gz") as archive:
        sql_members = [member for member in archive.getnames() if member.endswith(".sql")]
        assert len(sql_members) == 1
        sql_file = archive.extractfile(sql_members[0])
        assert sql_file is not None
        assert b"CREATE TABLE streamed" in sql_file.read()
    assert not list(layout.backups_dir(domain).glob("*.part"))
    assert not list(layout.backups_dir(domain).glob("*.sql"))


def test_backup_discards_failed_partial_database_dump(tmp_wpfy_home, monkeypatch):
    import wpfy.site_layout as layout

    importlib.reload(layout)
    domain = "failed-stream-backup.example.com"
    _ready_site(layout, domain, "wp", mysql=True, redis=False)

    def fake_run(args, **kwargs):
        if "mariadb-dump" in args[-1]:
            kwargs["stdout"].write("incomplete sql\n")
            return Proc(returncode=1, stderr="dump failed")
        return Proc()

    monkeypatch.setattr(layout, "docker_available", lambda: True)
    monkeypatch.setattr(layout, "runtime_skip_requested", lambda: False)
    monkeypatch.setattr(layout.subprocess, "run", fake_run)

    result = layout.backup_site(domain)

    assert result.exit_code != 0
    assert "dump failed" in result.message
    assert not list(layout.backups_dir(domain).glob("*.tar.gz"))
    assert not list(layout.backups_dir(domain).glob("*.sql"))
    assert not list(layout.backups_dir(domain).glob("*.part"))


def test_strict_backup_rejects_offline_database_site(tmp_wpfy_home, monkeypatch):
    import wpfy.site_layout as layout

    importlib.reload(layout)
    domain = "strict-backup.example.com"
    _ready_site(layout, domain, "wp", mysql=True, redis=False)
    monkeypatch.setenv("WPFY_SKIP_RUNTIME", "1")

    result = layout.backup_site(domain, require_database=True)

    assert result.exit_code != 0
    assert "database backup required" in result.message
    assert not list(layout.backups_dir(domain).glob("*"))


def test_restore_streams_database_file_to_stdin(tmp_wpfy_home, tmp_path, monkeypatch):
    import wpfy.site_layout as layout

    importlib.reload(layout)
    domain = "stream-restore.example.com"
    _ready_site(layout, domain, "wp", mysql=True, redis=False)
    site_root = layout.site_dir(domain)
    sql_dir = site_root / "backups"
    sql_dir.mkdir()
    sql_dir.joinpath("snapshot.sql").write_text("SELECT 1;\n", encoding="utf-8")
    archive_path = tmp_path / "stream-restore.tar.gz"
    with tarfile.open(archive_path, "w:gz") as archive:
        archive.add(site_root, arcname=domain)

    def fake_run(args, **kwargs):
        assert "stdin" in kwargs
        assert "input" not in kwargs
        assert kwargs["stdin"].read() == "SELECT 1;\n"
        return Proc()

    monkeypatch.setattr(layout, "docker_available", lambda: True)
    monkeypatch.setattr(layout, "runtime_skip_requested", lambda: False)
    monkeypatch.setattr(layout, "compose_command", lambda *args: Proc())
    monkeypatch.setattr(layout, "start_site_runtime", lambda domain_arg: layout.RuntimeResult(0, "started", ran=True))
    monkeypatch.setattr(layout, "_wait_for_service", lambda *args: layout.RuntimeResult(0, "ready", ran=True))
    monkeypatch.setattr(layout.subprocess, "run", fake_run)

    result = layout.restore_site(domain, str(archive_path))

    assert result.exit_code == 0


def test_wordpress_download_copies_bounded_chunks(tmp_wpfy_home, monkeypatch):
    import wpfy.site_layout as layout

    importlib.reload(layout)
    domain = "stream-wordpress.example.com"
    spec = layout.SiteSpec(domain=domain, flavor="wp", use_mysql=True, use_redis=False)
    layout.ensure_site_scaffold(spec)
    payload = io.BytesIO()
    with tarfile.open(fileobj=payload, mode="w:gz") as archive:
        for name, content in (
            ("wordpress/index.php", b"<?php\n"),
            ("wordpress/wp-includes/version.php", b"<?php\n"),
        ):
            member = tarfile.TarInfo(name)
            member.size = len(content)
            archive.addfile(member, io.BytesIO(content))

    class Response(io.BytesIO):
        def __init__(self, value: bytes) -> None:
            super().__init__(value)
            self.read_sizes = []

        def read(self, size: int = -1) -> bytes:
            self.read_sizes.append(size)
            return super().read(size)

    archive_response = Response(payload.getvalue())
    responses = {
        layout.WORDPRESS_VERSION_URL: Response(
            b'{"offers":[{"response":"upgrade","locale":"en_US","current":"7.0.1"}]}'
        ),
        "https://wordpress.org/wordpress-7.0.1.tar.gz.sha1": Response(
            hashlib.sha1(payload.getvalue()).hexdigest().encode("ascii")
        ),
        "https://wordpress.org/wordpress-7.0.1.tar.gz": archive_response,
    }
    monkeypatch.setattr(layout, "urlopen", lambda url, **kwargs: responses[url])

    result = layout.bootstrap_site_files(domain)

    assert result.exit_code == 0
    assert result.ran is True
    assert archive_response.read_sizes
    assert all(size > 0 for size in archive_response.read_sizes)
