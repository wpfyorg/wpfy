from __future__ import annotations

import io
import importlib
import json
import stat
import sys
import tarfile
from dataclasses import dataclass
from pathlib import Path

import pytest
from wpfy.cli import build_parser, run


class FakeProc:
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def test_build_parser_returns_parser():
    parser = build_parser()
    assert parser is not None


def test_parser_retains_grouped_and_flat_subcommands():
    parser = build_parser()
    subparsers_actions = [action for action in parser._actions if hasattr(action, 'choices')]
    subcommand_names = []
    for action in subparsers_actions:
        if action.choices:
            subcommand_names.extend(action.choices.keys())
    assert {
        "site",
        "run",
        "backup",
        "cron",
        "smtp",
        "restore",
        "rm",
        "wp",
        "version",
        "compose",
        "up",
        "down",
        "exec",
        "cp",
        "pull",
        "config",
        "edit",
        "refresh",
        "healthcheck",
        "motd",
        "utility",
        "stack",
        "sftp",
        "clean",
        "info",
        "log",
        "secure",
        "maintenance",
        "update",
        "debug",
    }.issubset(subcommand_names)


def test_help_exits_zero():
    with pytest.raises(SystemExit) as exc_info:
        run(["--help"])
    assert exc_info.value.code == 0


def test_help_shows_examples_and_description(capsys):
    with pytest.raises(SystemExit) as exc_info:
        run(["--help"])
    output = capsys.readouterr().out

    assert exc_info.value.code == 0
    assert "Docker-first CLI for WordPress and server administration." in output
    assert "Examples:" in output
    assert "wpfy run example.com --wp" in output


def test_site_namespace_is_intentionally_retained(capsys):
    with pytest.raises(SystemExit) as exc_info:
        run(["site", "--help"])
    output = capsys.readouterr().out

    assert exc_info.value.code == 0
    assert "Retained grouped namespace" in output


def test_site_create_help_shows_examples(capsys):
    with pytest.raises(SystemExit) as exc_info:
        run(["site", "create", "--help"])
    output = capsys.readouterr().out

    assert exc_info.value.code == 0
    assert "Create a site, bootstrap its filesystem, and optionally provision WordPress." in output
    assert "WordPress administrator password" in output
    assert "Examples:" in output


@pytest.mark.parametrize(
    ("argv", "command_attr", "expected_command"),
    [
        (["site", "ssl", "example.com", "--status"], "site_command", "ssl"),
        (["site", "list"], "site_command", "list"),
        (["site", "show", "example.com"], "site_command", "show"),
        (["site", "status", "example.com"], "site_command", "status"),
        (["stack", "install", "--nginx"], "stack_command", "install"),
        (["stack", "status"], "stack_command", "status"),
    ],
)
def test_retained_grouped_commands_parse(argv, command_attr, expected_command):
    args = build_parser().parse_args(argv)

    assert getattr(args, command_attr) == expected_command


@pytest.mark.parametrize(
    "argv",
    [
        ["run", "example.com", "--wp"],
        ["backup", "example.com"],
        ["restore", "example.com", "--latest"],
        ["wp", "example.com", "plugin", "list"],
        ["rm", "example.com", "--force"],
        ["config", "example.com"],
    ],
)
def test_primary_flat_flows_parse(argv):
    assert build_parser().parse_args(argv).command == argv[0]


def test_stack_namespace_is_intentionally_retained(capsys):
    with pytest.raises(SystemExit) as exc_info:
        run(["stack", "--help"])
    output = capsys.readouterr().out

    assert exc_info.value.code == 0
    assert "Retained grouped namespace" in output


@pytest.mark.parametrize(
    "command",
    [
        "run",
        "backup",
        "restore",
        "rm",
        "wp",
        "version",
        "compose",
        "up",
        "down",
        "exec",
        "cp",
        "pull",
        "config",
        "edit",
        "refresh",
        "healthcheck",
        "motd",
        "utility",
    ],
)
def test_flat_alias_help_exits_zero(command):
    with pytest.raises(SystemExit) as exc_info:
        run([command, "--help"])
    assert exc_info.value.code == 0


@pytest.mark.parametrize(
    "argv",
    [
        ["healthcheck", "--help"],
        ["motd", "--help"],
        ["utility", "--help"],
        ["utility", "password", "--help"],
        ["utility", "username", "--help"],
        ["utility", "uid", "--help"],
        ["utility", "token", "--help"],
        ["utility", "htpasswd", "--help"],
    ],
)
def test_page5_help_exits_zero(argv):
    with pytest.raises(SystemExit) as exc_info:
        run(argv)
    assert exc_info.value.code == 0


def test_stack_install_help_shows_examples(capsys):
    with pytest.raises(SystemExit) as exc_info:
        run(["stack", "install", "--help"])
    output = capsys.readouterr().out

    assert exc_info.value.code == 0
    assert "Pull the Docker images needed by wpfy and start the shared edge proxy." in output
    assert "Examples:" in output
    assert "wpfy stack install --all" in output


def test_secure_command_exists():
    with pytest.raises(SystemExit) as exc_info:
        run(["secure", "--help"])
    assert exc_info.value.code == 0


def test_maintenance_command_exists():
    with pytest.raises(SystemExit) as exc_info:
        run(["maintenance", "--help"])
    assert exc_info.value.code == 0


def test_maintenance_parser_rejects_multiple_actions():
    with pytest.raises(SystemExit) as exc_info:
        run(["maintenance", "example.com", "--enable", "--disable"])
    assert exc_info.value.code == 2


def test_maintenance_failure_does_not_update_registry(monkeypatch, capsys):
    import wpfy.cli as cli

    updates = []
    monkeypatch.setattr(cli, "site_exists", lambda domain: True)
    monkeypatch.setattr(cli, "compose_command", lambda *args: FakeProc(7, stderr="compose failed"))
    monkeypatch.setattr(cli.registry, "update_site", lambda *args: updates.append(args))

    result = run(["maintenance", "example.com", "--enable"])

    assert result == 7
    assert updates == []
    assert "compose failed" in capsys.readouterr().out


def test_maintenance_updates_registry_after_compose_success(monkeypatch):
    import wpfy.cli as cli

    calls = []
    monkeypatch.setattr(cli, "site_exists", lambda domain: True)
    monkeypatch.setattr(cli, "compose_command", lambda *args: calls.append(("compose", args)) or FakeProc())
    monkeypatch.setattr(cli.registry, "update_site", lambda *args: calls.append(("registry", args)))

    assert run(["maintenance", "example.com", "--disable"]) == 0
    assert calls == [
        ("compose", ("example.com", "start", "app")),
        ("registry", ("example.com", {"maintenance": "disabled"})),
    ]


def test_update_command_exists():
    with pytest.raises(SystemExit) as exc_info:
        run(["update", "--help"])
    assert exc_info.value.code == 0


def test_site_wp_command_exists():
    with pytest.raises(SystemExit) as exc_info:
        run(["site", "wp", "--help"])
    assert exc_info.value.code == 0


def test_secure_parser_in_build():
    parser = build_parser()
    subparsers = [a for a in parser._actions if hasattr(a, 'choices')]
    commands = set()
    for sp in subparsers:
        if sp.choices:
            commands.update(sp.choices.keys())
    assert "secure" in commands
    assert "maintenance" in commands
    assert "update" in commands


def test_site_wp_parser_has_domain():
    parser = build_parser()
    for action in parser._actions:
        if hasattr(action, 'choices') and "site" in (action.choices or {}):
            site = action.choices["site"]
            for sa in site._actions:
                if hasattr(sa, 'choices') and "wp" in (sa.choices or {}):
                    wp_parser = sa.choices["wp"]
                    args = [a.dest for a in wp_parser._actions if a.dest != "help"]
                    assert "domain" in args
                    assert "wp_args" in args
                    return
    pytest.fail("site wp parser not found")


def test_site_update_parser_has_flags():
    parser = build_parser()
    for action in parser._actions:
        if hasattr(action, 'choices') and "site" in (action.choices or {}):
            site = action.choices["site"]
            for sa in site._actions:
                if hasattr(sa, 'choices') and "update" in (sa.choices or {}):
                    update_parser = sa.choices["update"]
                    args = [a.dest for a in update_parser._actions if a.dest != "help"]
                    assert "domain" in args
                    assert "wpredis" in args
                    assert "wpfc" in args
                    assert "letsencrypt" in args
                    return
    pytest.fail("site update parser not found")


def test_site_create_parser_has_wordpress_admin_flags():
    parser = build_parser()
    for action in parser._actions:
        if hasattr(action, 'choices') and "site" in (action.choices or {}):
            site = action.choices["site"]
            for sa in site._actions:
                if hasattr(sa, 'choices') and "create" in (sa.choices or {}):
                    create_parser = sa.choices["create"]
                    args = [a.dest for a in create_parser._actions if a.dest != "help"]
                    assert "wp_user" in args
                    assert "wp_email" in args
                    assert "wp_password" in args
                    return
    pytest.fail("site create parser not found")


def test_php_parsers_accept_84_and_default_to_84():
    parser = build_parser()

    create_args = parser.parse_args(["site", "create", "example.com", "--wp"])
    assert create_args.php == "8.4"

    assert parser.parse_args(["site", "create", "example.com", "--php", "8.4"]).php == "8.4"
    assert parser.parse_args(["site", "update", "example.com", "--php", "8.4"]).php == "8.4"
    assert parser.parse_args(["stack", "install", "--php"]).php == "8.4"
    assert parser.parse_args(["stack", "install", "--php", "8.4"]).php == "8.4"


def test_site_create_default_php_version_is_84(monkeypatch):
    import wpfy.cli as cli

    captured = {}
    def fake_create(request, **kwargs):
        captured["request"] = request
        return cli.site_lifecycle.CreateSiteResult(
            spec=cli.site_lifecycle.SiteSpec(
                request.domain, request.flavor, True, False, php_version=request.php_version
            ),
            touched=(),
            bootstrap=cli.site_lifecycle.RuntimeResult(0, "ok", ran=True),
            runtime=cli.site_lifecycle.RuntimeResult(0, "started", ran=True),
            wordpress_message="installed",
        )

    monkeypatch.setattr(cli.site_lifecycle, "create_site", fake_create)

    result = cli.run(["site", "create", "example.com", "--wp"])

    assert result == 0
    assert captured["request"].php_version == "8.4"


def test_run_alias_uses_site_create_path(monkeypatch):
    import wpfy.cli as cli

    captured = {}

    def fake_create(request, **kwargs):
        captured["request"] = request
        return cli.site_lifecycle.CreateSiteResult(
            spec=cli.site_lifecycle.SiteSpec(
                request.domain, request.flavor, True, False, php_version=request.php_version
            ),
            touched=(),
            bootstrap=cli.site_lifecycle.RuntimeResult(0, "ok", ran=True),
            runtime=cli.site_lifecycle.RuntimeResult(0, "started", ran=True),
            wordpress_message="installed",
        )

    monkeypatch.setattr(cli.site_lifecycle, "create_site", fake_create)

    result = cli.run(["run", "example.com", "--wp"])

    assert result == 0
    assert captured["request"].domain == "example.com"
    assert captured["request"].flavor == "wp"
    assert captured["request"].php_version == "8.4"


def test_backup_alias_uses_site_backup_path(monkeypatch, capsys):
    import wpfy.cli as cli
    from wpfy.site_layout import RuntimeResult

    calls = []
    monkeypatch.setattr(
        cli,
        "backup_site",
        lambda domain, **kwargs: calls.append((domain, kwargs)) or RuntimeResult(0, "backup created", ran=True),
    )

    result = cli.run(["backup", "example.com"])
    output = capsys.readouterr().out

    assert result == 0
    assert calls == [("example.com", {"destination_dir": None, "upload_s3": False})]
    assert "=== site backup ===" in output
    assert "backup: OK backup created" in output


def test_backup_list_alias_prints_archive_paths(monkeypatch, capsys):
    import wpfy.cli as cli

    monkeypatch.setattr(cli, "list_backup_archives", lambda domain: [Path("/tmp/example.com/archive.tar.gz")])

    result = cli.run(["backup", "example.com", "--list"])
    output = capsys.readouterr().out

    assert result == 0
    assert "=== backup archives ===" in output
    assert "/tmp/example.com/archive.tar.gz" in output


def test_grouped_backup_list_prints_archive_paths(monkeypatch, capsys):
    import wpfy.cli as cli

    monkeypatch.setattr(cli, "list_backup_archives", lambda domain: [Path("/tmp/grouped/archive.tar.gz")])

    result = cli.run(["site", "backup", "example.com", "--list"])
    output = capsys.readouterr().out

    assert result == 0
    assert "/tmp/grouped/archive.tar.gz" in output


def test_backup_alias_passes_destination_and_s3(monkeypatch, capsys):
    import wpfy.cli as cli
    from wpfy.site_layout import RuntimeResult

    captured = {}

    def fake_backup(domain, **kwargs):
        captured["domain"] = domain
        captured["kwargs"] = kwargs
        return RuntimeResult(0, "backup created", ran=True)

    monkeypatch.setattr(cli, "backup_site", fake_backup)

    result = cli.run(["backup", "example.com", "--path", "/tmp/export", "--s3"])
    capsys.readouterr()

    assert result == 0
    assert captured == {
        "domain": "example.com",
        "kwargs": {"destination_dir": "/tmp/export", "upload_s3": True},
    }


def test_backup_alias_passes_retention_and_profile(monkeypatch, capsys):
    import wpfy.cli as cli
    from wpfy.site_layout import RuntimeResult

    captured = {}
    monkeypatch.setattr(
        cli,
        "backup_site",
        lambda domain, **kwargs: captured.update(domain=domain, kwargs=kwargs)
        or RuntimeResult(0, "backup created", ran=True),
    )

    result = cli.run(["backup", "example.com", "--s3", "--profile", "weekly", "--keep-local", "2"])
    capsys.readouterr()

    assert result == 0
    assert captured == {
        "domain": "example.com",
        "kwargs": {"destination_dir": None, "upload_s3": True, "s3_profile": "weekly", "keep_local": 2},
    }


def test_backup_all_continues_after_failure(monkeypatch, capsys):
    import wpfy.cli as cli
    from wpfy.site_layout import RuntimeResult

    calls = []
    monkeypatch.setattr(
        cli,
        "list_sites",
        lambda: [{"domain": "b.example.com"}, {"domain": "a.example.com"}, {"domain": "c.example.com"}],
    )

    def fake_backup(domain, **kwargs):
        calls.append((domain, kwargs))
        if domain == "b.example.com":
            return RuntimeResult(4, "offsite failed", ran=True)
        return RuntimeResult(0, "backup created", ran=True)

    monkeypatch.setattr(cli, "backup_site", fake_backup)

    result = cli.run(["backup", "all", "--path", "/tmp/export", "--s3"])
    output = capsys.readouterr().out

    assert result == 1
    assert [call[0] for call in calls] == ["a.example.com", "b.example.com", "c.example.com"]
    assert all(call[1] == {"destination_dir": "/tmp/export", "upload_s3": True} for call in calls)
    assert "b.example.com: FAIL offsite failed" in output
    assert "c.example.com: OK backup created" in output


def test_backup_all_empty_site_list_exits_zero(monkeypatch, capsys):
    import wpfy.cli as cli

    monkeypatch.setattr(cli, "list_sites", lambda: [])

    result = cli.run(["backup", "all"])
    output = capsys.readouterr().out

    assert result == 0
    assert "no managed sites found" in output


def test_restore_latest_uses_newest_archive(monkeypatch, capsys):
    import wpfy.cli as cli
    from wpfy.site_layout import RuntimeResult

    calls = []
    monkeypatch.setattr(cli, "latest_backup_archive", lambda domain: RuntimeResult(0, "/tmp/newest.tar.gz", ran=True))
    monkeypatch.setattr(
        cli,
        "restore_site",
        lambda domain, archive: calls.append((domain, archive)) or RuntimeResult(0, "restored", ran=True),
    )

    result = cli.run(["restore", "example.com", "--latest"])
    output = capsys.readouterr().out

    assert result == 0
    assert calls == [("example.com", "/tmp/newest.tar.gz")]
    assert "restore: OK restored" in output


def test_backup_storage_set_writes_secret_from_stdin(tmp_wpfy_home, monkeypatch, capsys):
    import wpfy.cli as cli
    import wpfy.s3_backup

    importlib.reload(wpfy.s3_backup)
    monkeypatch.setattr(sys, "stdin", io.StringIO("stored-secret\n"))

    result = cli.run([
        "backup",
        "storage",
        "set",
        "--endpoint",
        "https://storage.example.test",
        "--bucket",
        "site-backups",
        "--region",
        "auto",
        "--prefix",
        "daily",
        "--access-key",
        "stored-access",
        "--secret-key-stdin",
    ])
    output = capsys.readouterr().out
    stored = wpfy.s3_backup.load_s3_config()

    assert result == 0
    assert stored.bucket == "site-backups"
    assert stored.secret_key == "stored-secret"
    assert stat.S_IMODE(wpfy.s3_backup.s3_config_path().stat().st_mode) == 0o600
    assert "stored-secret" not in output
    assert "stored-access" not in output
    assert "secret key: configured" in output


def test_backup_storage_profile_uses_profile_path(tmp_wpfy_home, monkeypatch, capsys):
    import wpfy.cli as cli
    import wpfy.s3_backup

    importlib.reload(wpfy.s3_backup)
    monkeypatch.setattr(sys, "stdin", io.StringIO("stored-secret\n"))

    result = cli.run([
        "backup",
        "storage",
        "set",
        "--endpoint",
        "https://storage.example.test",
        "--bucket",
        "site-backups",
        "--region",
        "auto",
        "--prefix",
        "weekly",
        "--access-key",
        "stored-access",
        "--profile",
        "weekly",
        "--secret-key-stdin",
    ])
    output = capsys.readouterr().out

    assert result == 0
    assert "backup-storage.d/weekly.env" in output
    assert wpfy.s3_backup.load_s3_config("weekly").prefix == "weekly"


def test_backup_storage_status_redacts_secret(tmp_wpfy_home, capsys):
    import wpfy.cli as cli
    import wpfy.s3_backup

    importlib.reload(wpfy.s3_backup)
    wpfy.s3_backup.write_s3_config(
        wpfy.s3_backup.S3Config(
            endpoint="https://storage.example.test",
            bucket="site-backups",
            region="auto",
            prefix="daily",
            access_key="stored-access",
            secret_key="stored-secret",
        )
    )

    result = cli.run(["backup", "storage", "status"])
    output = capsys.readouterr().out

    assert result == 0
    assert "bucket: site-backups" in output
    assert "secret key: configured" in output
    assert "stored-secret" not in output
    assert "stored-access" not in output


def test_backup_storage_test_uses_fake_uploader(tmp_wpfy_home, monkeypatch, capsys):
    import wpfy.cli as cli
    import wpfy.s3_backup

    importlib.reload(wpfy.s3_backup)
    wpfy.s3_backup.write_s3_config(
        wpfy.s3_backup.S3Config(
            endpoint="https://storage.example.test",
            bucket="site-backups",
            region="auto",
            prefix="daily",
            access_key="stored-access",
            secret_key="stored-secret",
        )
    )
    calls = []

    class FakeUploader:
        def upload_bytes(self, config, key, payload):
            calls.append((config.bucket, key, payload))
            return f"s3://{config.bucket}/{key}"

    monkeypatch.setattr(cli, "S3Uploader", lambda: FakeUploader())

    result = cli.run(["backup", "storage", "test"])
    output = capsys.readouterr().out

    assert result == 0
    assert calls == [("site-backups", "daily/.wpfy-test", b"wpfy backup storage test\n")]
    assert "upload: OK s3://site-backups/daily/.wpfy-test" in output
    assert "stored-secret" not in output


def test_backup_storage_missing_config_exits_two(tmp_wpfy_home, capsys):
    import wpfy.cli as cli
    import wpfy.s3_backup

    importlib.reload(wpfy.s3_backup)

    result = cli.run(["backup", "storage", "status"])
    output = capsys.readouterr().out

    assert result == 2
    assert "backup storage is not configured" in output


def test_backup_remote_list_reads_managed_prefix(tmp_wpfy_home, monkeypatch, capsys):
    import wpfy.cli as cli
    import wpfy.s3_backup

    importlib.reload(wpfy.s3_backup)
    wpfy.s3_backup.write_s3_config(
        wpfy.s3_backup.S3Config(
            endpoint="https://storage.example.test",
            bucket="site-backups",
            region="auto",
            prefix="daily",
            access_key="stored-access",
            secret_key="stored-secret",
        )
    )
    prefixes = []

    class FakeUploader:
        def list_keys(self, config, prefix):
            prefixes.append(prefix)
            return [
                "daily/example.com/example.com-20260701000000.tar.gz",
                "daily/example.com/nested/bad.tar.gz",
                "daily/other.com/other.tar.gz",
            ]

    monkeypatch.setattr(cli, "S3Uploader", FakeUploader)

    result = cli.run(["backup", "remote", "list", "example.com"])
    output = capsys.readouterr().out

    assert result == 0
    assert prefixes == ["daily/example.com/"]
    assert "s3://site-backups/daily/example.com/example.com-20260701000000.tar.gz" in output
    assert "nested/bad" not in output


def test_backup_remote_delete_requires_force(tmp_wpfy_home, monkeypatch, capsys):
    import wpfy.cli as cli
    import wpfy.s3_backup

    importlib.reload(wpfy.s3_backup)
    wpfy.s3_backup.write_s3_config(
        wpfy.s3_backup.S3Config(
            endpoint="https://storage.example.test",
            bucket="site-backups",
            region="auto",
            prefix="daily",
            access_key="stored-access",
            secret_key="stored-secret",
        )
    )

    result = cli.run([
        "backup",
        "remote",
        "delete",
        "example.com",
        "--key",
        "daily/example.com/example.com-20260701000000.tar.gz",
    ])
    output = capsys.readouterr().out

    assert result == 2
    assert "backup remote delete aborted: --force required" in output


def test_backup_remote_restore_uses_private_temp_file_and_cleans_up(monkeypatch, capsys):
    import wpfy.cli as cli
    from wpfy.s3_backup import S3Config

    config = S3Config(
        endpoint="https://storage.example.test",
        bucket="site-backups",
        region="auto",
        prefix="daily",
        access_key="access-key",
        secret_key="secret-key",
    )
    key = "daily/example.com/example.com-20260701000000.tar.gz"
    observed = {}

    class FakeUploader:
        def list_keys(self, config_arg, prefix):
            return [key]

        def download_to_path(self, config_arg, key_arg, destination):
            destination.write_bytes(b"completed remote archive")
            observed["path"] = destination
            return destination

    uploader = FakeUploader()
    monkeypatch.setattr(cli, "_load_remote", lambda profile: (config, uploader, None))

    def restore_site(domain, archive_path):
        path = Path(archive_path)
        observed["mode"] = stat.S_IMODE(path.stat().st_mode)
        observed["payload"] = path.read_bytes()
        return cli.RuntimeResult(0, "restored", ran=True)

    monkeypatch.setattr(cli, "restore_site", restore_site)

    result = cli.run(["backup", "remote", "restore", "example.com", "--latest"])
    output = capsys.readouterr().out

    assert result == 0
    assert observed["mode"] == 0o600
    assert observed["payload"] == b"completed remote archive"
    assert not observed["path"].exists()
    assert "restore: OK restored" in output


def _site_backup_bytes(domain):
    payload = io.BytesIO()
    with tarfile.open(fileobj=payload, mode="w:gz") as archive:
        content = b"restored"
        member = tarfile.TarInfo(f"{domain}/app/restored.txt")
        member.size = len(content)
        archive.addfile(member, io.BytesIO(content))
    return payload.getvalue()


def test_backup_remote_restore_uses_real_archive_validator(tmp_wpfy_home, monkeypatch, capsys):
    import wpfy.cli as cli
    import wpfy.site_layout as layout
    from wpfy.s3_backup import S3Config

    domain = "example.com"
    config = S3Config(
        endpoint="https://storage.example.test",
        bucket="site-backups",
        region="auto",
        prefix="daily",
        access_key="access-key",
        secret_key="secret-key",
    )
    key = f"daily/{domain}/{domain}-20260701000000.tar.gz"
    observed = {}

    class FakeUploader:
        def list_keys(self, config_arg, prefix):
            return [key]

        def download_to_path(self, config_arg, key_arg, destination):
            destination.write_bytes(_site_backup_bytes(domain))
            observed["path"] = destination
            return destination

    monkeypatch.setattr(cli, "_load_remote", lambda profile: (config, FakeUploader(), None))
    monkeypatch.setattr(layout, "docker_available", lambda: False)

    result = cli.run(["backup", "remote", "restore", domain, "--latest"])
    output = capsys.readouterr().out

    assert result == 0
    assert layout.site_dir(domain).joinpath("app/restored.txt").read_bytes() == b"restored"
    assert not observed["path"].exists()
    assert "restore: OK" in output


@pytest.mark.parametrize(
    "payload",
    [b"not a gzip archive", _site_backup_bytes("example.com")[:64]],
    ids=["malformed", "truncated"],
)
def test_backup_remote_restore_rejects_invalid_archive_before_runtime_stop(
    tmp_wpfy_home, monkeypatch, capsys, payload
):
    import wpfy.cli as cli
    import wpfy.site_layout as layout
    from wpfy.s3_backup import S3Config

    domain = "example.com"
    config = S3Config(
        endpoint="https://storage.example.test",
        bucket="site-backups",
        region="auto",
        prefix="daily",
        access_key="access-key",
        secret_key="secret-key",
    )
    key = f"daily/{domain}/{domain}-20260701000000.tar.gz"
    live_marker = layout.site_dir(domain) / "live-marker"
    live_marker.parent.mkdir(parents=True)
    live_marker.write_bytes(b"live")
    observed = {}

    class FakeUploader:
        def list_keys(self, config_arg, prefix):
            return [key]

        def download_to_path(self, config_arg, key_arg, destination):
            destination.write_bytes(payload)
            observed["path"] = destination
            return destination

    monkeypatch.setattr(cli, "_load_remote", lambda profile: (config, FakeUploader(), None))
    monkeypatch.setattr(layout, "docker_available", lambda: True)
    monkeypatch.setattr(layout, "runtime_skip_requested", lambda: False)
    monkeypatch.setattr(
        layout,
        "compose_command",
        lambda *args: pytest.fail("runtime stopped before archive validation"),
    )

    result = cli.run(["backup", "remote", "restore", domain, "--latest"])
    output = capsys.readouterr().out

    assert result != 0
    assert live_marker.read_bytes() == b"live"
    assert not observed["path"].exists()
    assert "restore: FAIL invalid backup archive" in output


def test_backup_remote_restore_cleans_interrupted_download(monkeypatch, capsys):
    import wpfy.cli as cli
    from wpfy.s3_backup import S3Config

    config = S3Config(
        endpoint="https://storage.example.test",
        bucket="site-backups",
        region="auto",
        prefix="daily",
        access_key="access-key",
        secret_key="secret-key",
    )
    key = "daily/example.com/example.com-20260701000000.tar.gz"
    observed = {}

    class FakeUploader:
        def list_keys(self, config_arg, prefix):
            return [key]

        def download_to_path(self, config_arg, key_arg, destination):
            destination.write_bytes(b"partial")
            observed["path"] = destination
            raise OSError(f"interrupted for {config_arg.secret_key}")

    uploader = FakeUploader()
    monkeypatch.setattr(cli, "_load_remote", lambda profile: (config, uploader, None))
    monkeypatch.setattr(cli, "restore_site", lambda *args: pytest.fail("restore called"))

    result = cli.run(["backup", "remote", "restore", "example.com", "--latest"])
    output = capsys.readouterr().out

    assert result == 4
    assert not observed["path"].exists()
    assert "download: FAIL interrupted" in output
    assert "secret-key" not in output


def test_backup_remote_restore_cleans_unexpected_restore_error(monkeypatch, capsys):
    import wpfy.cli as cli
    from wpfy.s3_backup import S3Config

    config = S3Config(
        endpoint="https://storage.example.test",
        bucket="site-backups",
        region="auto",
        prefix="daily",
        access_key="access-key",
        secret_key="secret-key",
    )
    key = "daily/example.com/example.com-20260701000000.tar.gz"
    observed = {}

    class FakeUploader:
        def list_keys(self, config_arg, prefix):
            return [key]

        def download_to_path(self, config_arg, key_arg, destination):
            destination.write_bytes(b"complete")
            observed["path"] = destination
            return destination

    uploader = FakeUploader()
    monkeypatch.setattr(cli, "_load_remote", lambda profile: (config, uploader, None))
    monkeypatch.setattr(
        cli,
        "restore_site",
        lambda *args: (_ for _ in ()).throw(RuntimeError("restore exploded")),
    )

    result = cli.run(["backup", "remote", "restore", "example.com", "--latest"])
    output = capsys.readouterr().out

    assert result == 4
    assert not observed["path"].exists()
    assert "restore: FAIL restore exploded" in output


def test_dns_cloudflare_set_status_redacts_token(tmp_wpfy_home, monkeypatch, capsys):
    import wpfy.cli as cli

    importlib.reload(cli.dns)
    monkeypatch.setattr(sys, "stdin", io.StringIO("cf-secret-token\n"))

    result = cli.run(["dns", "cloudflare", "set", "--token-stdin"])
    output = capsys.readouterr().out

    assert result == 0
    assert "token: configured" in output
    assert "cf-secret-token" not in output
    assert stat.S_IMODE(cli.dns.cloudflare_config_path().stat().st_mode) == 0o600


def test_backup_storage_clear_requires_force(tmp_wpfy_home, capsys):
    import wpfy.cli as cli

    result = cli.run(["backup", "storage", "clear"])
    output = capsys.readouterr().out

    assert result == 2
    assert "--force required" in output


def test_backup_schedule_daily_writes_systemd_units(tmp_wpfy_home, monkeypatch, tmp_path, capsys):
    import wpfy.cli as cli
    import wpfy.backup_schedule
    import wpfy.s3_backup
    import wpfy.systemd

    importlib.reload(wpfy.backup_schedule)
    importlib.reload(wpfy.s3_backup)
    monkeypatch.setenv("WPFY_SYSTEMD_DIR", str(tmp_path / "systemd"))
    wpfy.s3_backup.write_s3_config(
        wpfy.s3_backup.S3Config(
            endpoint="https://storage.example.test",
            bucket="site-backups",
            region="auto",
            prefix="daily",
            access_key="stored-access",
            secret_key="stored-secret",
        )
    )
    commands = []
    monkeypatch.setattr(wpfy.systemd.subprocess, "run", lambda cmd, **kwargs: commands.append(cmd) or FakeProc())

    result = cli.run(["backup", "schedule", "daily", "--time", "02:30", "--path", "/backups", "--s3"])
    output = capsys.readouterr().out
    service = (tmp_path / "systemd" / "wpfy-backup.service").read_text(encoding="utf-8")
    timer = (tmp_path / "systemd" / "wpfy-backup.timer").read_text(encoding="utf-8")

    assert result == 0
    assert "ExecStart=/usr/local/bin/wpfy backup all --path /backups --s3" in service
    assert "OnCalendar=*-*-* 02:30:00" in timer
    assert commands == [["systemctl", "daemon-reload"], ["systemctl", "enable", "--now", "wpfy-backup.timer"]]
    assert "schedule: enabled daily at 02:30" in output


def test_backup_schedule_weekly_writes_weekday_timer(tmp_wpfy_home, monkeypatch, tmp_path, capsys):
    import wpfy.cli as cli
    import wpfy.backup_schedule
    import wpfy.systemd

    importlib.reload(wpfy.backup_schedule)
    monkeypatch.setenv("WPFY_SYSTEMD_DIR", str(tmp_path / "systemd"))
    commands = []
    monkeypatch.setattr(wpfy.systemd.subprocess, "run", lambda cmd, **kwargs: commands.append(cmd) or FakeProc())

    result = cli.run(["backup", "schedule", "weekly", "--weekday", "sun", "--time", "03:00"])
    output = capsys.readouterr().out
    timer = (tmp_path / "systemd" / "wpfy-backup.timer").read_text(encoding="utf-8")

    assert result == 0
    assert "OnCalendar=sun *-*-* 03:00:00" in timer
    assert "schedule: enabled weekly on sun at 03:00" in output
    assert commands == [["systemctl", "daemon-reload"], ["systemctl", "enable", "--now", "wpfy-backup.timer"]]


def test_backup_schedule_disable_leaves_storage_config(tmp_wpfy_home, monkeypatch, tmp_path, capsys):
    import wpfy.cli as cli
    import wpfy.backup_schedule
    import wpfy.s3_backup
    import wpfy.systemd

    importlib.reload(wpfy.backup_schedule)
    importlib.reload(wpfy.s3_backup)
    monkeypatch.setenv("WPFY_SYSTEMD_DIR", str(tmp_path / "systemd"))
    wpfy.s3_backup.write_s3_config(
        wpfy.s3_backup.S3Config(
            endpoint="https://storage.example.test",
            bucket="site-backups",
            region="auto",
            prefix="daily",
            access_key="stored-access",
            secret_key="stored-secret",
        )
    )
    commands = []
    monkeypatch.setattr(wpfy.systemd.subprocess, "run", lambda cmd, **kwargs: commands.append(cmd) or FakeProc())

    result = cli.run(["backup", "schedule", "disable"])
    output = capsys.readouterr().out

    assert result == 0
    assert wpfy.s3_backup.s3_config_path().exists()
    assert commands == [
        ["systemctl", "disable", "--now", "wpfy-backup.timer"],
        ["systemctl", "daemon-reload"],
    ]
    assert "schedule: disabled" in output


def test_backup_schedule_rejects_bad_time(capsys):
    import wpfy.cli as cli

    result = cli.run(["backup", "schedule", "daily", "--time", "25:99"])
    output = capsys.readouterr().out

    assert result == 2
    assert "invalid time" in output


def test_backup_schedule_s3_requires_storage_config(tmp_wpfy_home, capsys):
    import wpfy.cli as cli
    import wpfy.s3_backup

    importlib.reload(wpfy.s3_backup)

    result = cli.run(["backup", "schedule", "daily", "--time", "02:30", "--s3"])
    output = capsys.readouterr().out

    assert result == 2
    assert "backup storage is not configured" in output


def test_cron_interval_runs_sorted_wordpress_sites_and_skips_non_wp(tmp_wpfy_home, monkeypatch, capsys):
    import wpfy.cli as cli
    import wpfy.cron

    importlib.reload(wpfy.cron)
    calls = []
    monkeypatch.setattr(wpfy.cron.shutil, "which", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(
        wpfy.cron,
        "list_sites",
        lambda: [
            {"domain": "z.example.com", "flavor": "wp"},
            {"domain": "a.example.com", "flavor": "wpredis"},
            {"domain": "static.example.com", "flavor": "html"},
        ],
    )
    monkeypatch.setattr(
        wpfy.cron,
        "wp_cli_command",
        lambda domain, *args: calls.append((domain, args)) or FakeProc(stdout="ok"),
    )

    result = cli.run(["cron", "minute"])
    output = capsys.readouterr().out

    assert result == 0
    assert calls == [
        ("a.example.com", ("cron", "event", "run", "--due-now", "--allow-root")),
        ("z.example.com", ("cron", "event", "run", "--due-now", "--allow-root")),
    ]
    assert "a.example.com: wp cron OK" in output
    assert "static.example.com" not in output


def test_cron_install_writes_all_interval_timers(tmp_wpfy_home, monkeypatch, tmp_path, capsys):
    import wpfy.cli as cli
    import wpfy.cron
    import wpfy.systemd

    importlib.reload(wpfy.cron)
    monkeypatch.setenv("WPFY_SYSTEMD_DIR", str(tmp_path / "systemd"))
    commands = []
    monkeypatch.setattr(wpfy.systemd.subprocess, "run", lambda cmd, **kwargs: commands.append(cmd) or FakeProc())

    result = cli.run(["cron", "install"])
    output = capsys.readouterr().out
    service = (tmp_path / "systemd" / "wpfy-cron-five-minute.service").read_text(encoding="utf-8")
    timer = (tmp_path / "systemd" / "wpfy-cron-five-minute.timer").read_text(encoding="utf-8")

    assert result == 0
    assert "ExecStart=/usr/local/bin/wpfy cron five-minute" in service
    assert "OnCalendar=*-*-* *:0/5:00" in timer
    assert commands == [
        ["systemctl", "daemon-reload"],
        ["systemctl", "enable", "--now", *wpfy.cron.timer_names()],
    ]
    assert "cron timers installed" in output


def test_cron_refuses_world_writable_custom_hook(tmp_wpfy_home, monkeypatch, capsys):
    import wpfy.cli as cli
    import wpfy.cron

    importlib.reload(wpfy.cron)
    monkeypatch.setenv("WPFY_SKIP_RUNTIME", "1")
    hook = Path(tmp_wpfy_home.config_dir) / "custom" / "cron" / "daily.sh"
    hook.parent.mkdir(parents=True)
    hook.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    hook.chmod(0o777)
    monkeypatch.setattr(wpfy.cron, "list_sites", lambda: [])

    result = cli.run(["cron", "daily"])
    output = capsys.readouterr().out
    log = (Path(tmp_wpfy_home.log_dir) / "cron.log").read_text(encoding="utf-8")

    assert result == 1
    assert "custom hook: refused unsafe hook" in output
    assert "custom hook: refused unsafe hook" in log


def test_log_cron_reads_tail(tmp_wpfy_home, capsys):
    import wpfy.cli as cli
    import wpfy.cron

    importlib.reload(wpfy.cron)
    log = Path(tmp_wpfy_home.log_dir) / "cron.log"
    log.parent.mkdir(parents=True)
    log.write_text("one\ntwo\nthree\n", encoding="utf-8")

    result = cli.run(["log", "cron", "--lines", "2"])
    output = capsys.readouterr().out

    assert result == 0
    assert output == "two\nthree\n"


def test_smtp_set_writes_config_mode_and_redacts_status(tmp_wpfy_home, monkeypatch, capsys):
    import wpfy.cli as cli
    import wpfy.smtp

    importlib.reload(wpfy.smtp)
    monkeypatch.setattr(sys, "stdin", io.StringIO("smtp-secret\n"))

    result = cli.run([
        "smtp",
        "set",
        "--host",
        "smtp.example.test",
        "--port",
        "587",
        "--sender",
        "ops@example.test",
        "--username",
        "smtp-user",
        "--password-stdin",
    ])
    output = capsys.readouterr().out
    path = wpfy.smtp.smtp_config_path()

    assert result == 0
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert "username: configured" in output
    assert "password: configured" in output
    assert "smtp-secret" not in output

    status_result = cli.run(["smtp", "status"])
    status_output = capsys.readouterr().out

    assert status_result == 0
    assert "smtp-user" not in status_output
    assert "smtp-secret" not in status_output


def test_smtp_status_missing_config_exits_two(tmp_wpfy_home, capsys):
    import wpfy.cli as cli
    import wpfy.smtp

    importlib.reload(wpfy.smtp)

    result = cli.run(["smtp", "status"])
    output = capsys.readouterr().out

    assert result == 2
    assert "smtp is not configured" in output


def test_smtp_test_dry_run_avoids_network(tmp_wpfy_home, monkeypatch, capsys):
    import wpfy.cli as cli
    import wpfy.smtp

    importlib.reload(wpfy.smtp)
    wpfy.smtp.write_smtp_config(
        wpfy.smtp.SMTPConfig(
            host="smtp.example.test",
            port=587,
            sender="ops@example.test",
            username="smtp-user",
            password="smtp-secret",
        )
    )
    monkeypatch.setattr(wpfy.smtp.smtplib, "SMTP", lambda *args, **kwargs: pytest.fail("network should not run"))

    result = cli.run(["smtp", "test", "--dry-run"])
    output = capsys.readouterr().out

    assert result == 0
    assert "dry-run: validated SMTP config for ops@example.test" in output


def test_smtp_test_to_sends_with_fake_transport(tmp_wpfy_home, monkeypatch, capsys):
    import wpfy.cli as cli
    import wpfy.smtp

    importlib.reload(wpfy.smtp)
    wpfy.smtp.write_smtp_config(
        wpfy.smtp.SMTPConfig(
            host="127.0.0.1",
            port=2525,
            sender="ops@example.test",
            username="smtp-user",
            password="smtp-secret",
            tls="none",
        )
    )
    sent = []

    class FakeSMTP:
        def __init__(self, host, port, timeout):
            sent.append(("connect", host, port, timeout))

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def login(self, username, password):
            sent.append(("login", username, password))

        def send_message(self, message):
            sent.append(("send", message["To"], message["From"]))

    monkeypatch.setattr(wpfy.smtp.smtplib, "SMTP", FakeSMTP)

    result = cli.run(["smtp", "test", "--to", "owner@example.test"])
    output = capsys.readouterr().out

    assert result == 0
    assert sent == [
        ("connect", "127.0.0.1", 2525, 15),
        ("login", "smtp-user", "smtp-secret"),
        ("send", "owner@example.test", "ops@example.test"),
    ]
    assert "sent: owner@example.test" in output


def test_restore_alias_uses_site_restore_path(monkeypatch, capsys):
    import wpfy.cli as cli
    from wpfy.site_layout import RuntimeResult

    calls = []
    monkeypatch.setattr(
        cli,
        "restore_site",
        lambda domain, backup: calls.append((domain, backup)) or RuntimeResult(0, "restored", ran=True),
    )

    result = cli.run(["restore", "example.com", "/tmp/example-backup.tar.gz"])
    output = capsys.readouterr().out

    assert result == 0
    assert calls == [("example.com", "/tmp/example-backup.tar.gz")]
    assert "=== site restore ===" in output
    assert "restore: OK restored" in output


def test_restore_list_alias_prints_archive_paths(monkeypatch, capsys):
    import wpfy.cli as cli

    monkeypatch.setattr(cli, "list_backup_archives", lambda domain: [Path("/tmp/example.com/archive.tar.gz")])

    result = cli.run(["restore", "example.com", "--list"])
    output = capsys.readouterr().out

    assert result == 0
    assert "=== restore archives ===" in output
    assert "/tmp/example.com/archive.tar.gz" in output


def test_grouped_restore_list_prints_archive_paths(monkeypatch, capsys):
    import wpfy.cli as cli

    monkeypatch.setattr(cli, "list_backup_archives", lambda domain: [Path("/tmp/grouped/archive.tar.gz")])

    result = cli.run(["site", "restore", "example.com", "--list"])
    output = capsys.readouterr().out

    assert result == 0
    assert "/tmp/grouped/archive.tar.gz" in output


def test_restore_without_archive_exits_cleanly(capsys):
    import wpfy.cli as cli

    result = cli.run(["restore", "example.com"])
    output = capsys.readouterr().out

    assert result == 2
    assert "restore backup archive required unless --list is used" in output
    assert "Traceback" not in output


def test_stack_install_php_flag_pulls_default_84(monkeypatch, capsys):
    import wpfy.cli as cli

    calls = []

    class Proc:
        returncode = 0
        stdout = "ok"
        stderr = ""

    def fake_run(cmd, *args, **kwargs):
        calls.append(cmd)
        return Proc()

    monkeypatch.setattr(cli.stack.subprocess, "run", fake_run)

    result = cli.run(["stack", "install", "--php"])
    output = capsys.readouterr().out

    assert result == 0
    assert ["docker", "pull", "ghcr.io/wpfyorg/php-fpm:8.4"] in calls
    assert not any(cmd[:2] == ["docker", "build"] for cmd in calls)
    assert "=== stack install ===" in output
    assert "PHP 8.4: OK pulled ghcr.io/wpfyorg/php-fpm:8.4" in output


def test_stack_install_explicit_php_pulls_only_requested_version(monkeypatch):
    import wpfy.cli as cli

    calls = []

    class Proc:
        returncode = 0
        stdout = "ok"
        stderr = ""

    def fake_run(cmd, *args, **kwargs):
        calls.append(cmd)
        return Proc()

    monkeypatch.setattr(cli.stack.subprocess, "run", fake_run)

    result = cli.run(["stack", "install", "--php", "8.3"])

    assert result == 0
    assert calls == [["docker", "pull", "ghcr.io/wpfyorg/php-fpm:8.3"]]


def test_stack_install_all_pulls_only_default_php(monkeypatch):
    import wpfy.cli as cli
    from wpfy.site_layout import RuntimeResult

    calls = []

    class Proc:
        returncode = 0
        stdout = "ok"
        stderr = ""

    def fake_run(cmd, *args, **kwargs):
        calls.append(cmd)
        return Proc()

    monkeypatch.setattr(cli.stack.traefik, "start_traefik", lambda: RuntimeResult(0, "started", ran=True))
    monkeypatch.setattr(cli.stack.subprocess, "run", fake_run)

    result = cli.run(["stack", "install", "--all"])
    pulled = [cmd for cmd in calls if cmd[:2] == ["docker", "pull"]]

    assert result == 0
    assert ["docker", "pull", "ghcr.io/wpfyorg/php-fpm:8.4"] in pulled
    assert ["docker", "pull", "ghcr.io/wpfyorg/php-fpm:8.2"] not in pulled
    assert ["docker", "pull", "ghcr.io/wpfyorg/php-fpm:8.3"] not in pulled
    assert not any(cmd[:2] == ["docker", "build"] for cmd in calls)


def test_stack_install_shows_tty_progress(monkeypatch, capsys):
    import wpfy.cli as cli
    from wpfy.site_layout import RuntimeResult

    class Proc:
        returncode = 0
        stdout = "ok"
        stderr = ""

    monkeypatch.setattr(cli.sys.stderr, "isatty", lambda: True)
    monkeypatch.setattr(cli.stack.traefik, "start_traefik", lambda: RuntimeResult(0, "started", ran=True))
    monkeypatch.setattr(cli.stack.subprocess, "run", lambda *args, **kwargs: Proc())

    result = cli.run(["stack", "install", "--all"])
    progress = capsys.readouterr().err

    assert result == 0
    assert "Starting shared Traefik edge proxy..." in progress
    assert "Pulling PHP 8.4 runtime image..." in progress
    assert "Pulling mariadb:11.4 image..." in progress
    assert "Pulling redis:7.2-alpine image..." in progress


def test_stack_install_php_pull_failure_exits_nonzero(monkeypatch, capsys):
    import wpfy.cli as cli

    class Proc:
        returncode = 1
        stdout = ""
        stderr = "manifest unknown"

    monkeypatch.setattr(cli.stack.subprocess, "run", lambda *args, **kwargs: Proc())

    result = cli.run(["stack", "install", "--php"])
    output = capsys.readouterr().out

    assert result == 1
    assert "=== stack install ===" in output
    assert "PHP 8.4: FAIL error: manifest unknown" in output


def test_stack_install_cli_delegates_selection_to_stack(monkeypatch, capsys):
    import wpfy.cli as cli

    requests = []
    monkeypatch.setattr(
        cli.stack,
        "install",
        lambda request, *, progress: requests.append(request) or cli.stack.StackResult((
            cli.stack.StackFact("PHP 8.3", "OK", "pulled"),
        )),
    )

    result = cli.run(["stack", "install", "--php", "8.3"])

    assert result == 0
    assert requests == [cli.stack.StackInstallRequest(php_version="8.3")]
    assert "PHP 8.3: OK pulled" in capsys.readouterr().out


def test_stack_status_cli_propagates_failure(monkeypatch, capsys):
    import wpfy.cli as cli

    monkeypatch.setattr(
        cli.stack,
        "status",
        lambda: cli.stack.StackStatus(
            cli.stack.RuntimeResult(6, "failed", ran=True),
            None,
            (),
            "daemon down",
            "images failed",
        ),
    )

    result = cli.run(["stack", "status"])
    output = capsys.readouterr().out

    assert result == 6
    assert "Docker: FAIL daemon down" in output
    assert "Pulled wpfy images: FAIL images failed" in output


def test_stack_purge_passes_force_and_renders_failure(monkeypatch, capsys):
    import wpfy.cli as cli

    calls = []
    monkeypatch.setattr(
        cli.stack,
        "purge",
        lambda *, force: calls.append(force) or cli.stack.StackResult(
            (cli.stack.StackFact("Traefik", "FAIL", "--force is required", 2),),
            2,
        ),
    )

    result = cli.run(["stack", "purge"])
    output = capsys.readouterr().out

    assert result == 2
    assert calls == [False]
    assert "Traefik: FAIL --force is required" in output
    assert "compose project removed" not in output


def test_clean_mixed_failure_exits_nonzero(monkeypatch, capsys):
    import wpfy.cli as cli

    outcomes = (
        cli.cache_operations.CacheOutcome("a.test", "nginx", "ok", "cache cleared"),
        cli.cache_operations.CacheOutcome("z.test", "opcache", "error", "exec failed"),
    )
    monkeypatch.setattr(cli.cache_operations, "clear", lambda request: cli.cache_operations.CacheResult(outcomes))

    result = cli.run(["clean", "--all"])
    output = capsys.readouterr().out

    assert result == 1
    assert "[a.test] nginx cache cleared" in output
    assert "[z.test] opcache: exec failed" in output


def test_log_show_delegates_streaming_mode(monkeypatch):
    import wpfy.cli as cli
    from wpfy.site_runtime import ProcessResult

    calls = []
    monkeypatch.setattr(cli, "site_info", lambda domain: {"domain": domain})
    monkeypatch.setattr(
        cli,
        "site_logs",
        lambda domain, **kwargs: calls.append((domain, kwargs)) or ProcessResult(17, ran=True),
    )

    result = cli.run(["log", "show", "example.com", "--php", "--follow", "--lines", "42"])

    assert result == 17
    assert calls == [("example.com", {"services": ("app",), "lines": 42, "follow": True})]


def test_log_reset_skipped_stop_is_failure(monkeypatch, capsys):
    import wpfy.cli as cli
    from wpfy.site_runtime import LogResetResult, RuntimeResult

    monkeypatch.setattr(cli, "site_info", lambda domain: {"domain": domain})
    monkeypatch.setattr(
        cli,
        "reset_site_logs",
        lambda domain: LogResetResult(RuntimeResult(0, "runtime unavailable", skipped=True)),
    )

    result = cli.run(["log", "reset", "example.com"])

    assert result == 1
    assert "runtime: FAIL runtime unavailable" in capsys.readouterr().out


def test_wordpress_credentials_use_git_defaults_non_interactive(monkeypatch):
    import argparse
    import wpfy.cli as cli

    class Proc:
        def __init__(self, returncode=0, stdout=""):
            self.returncode = returncode
            self.stdout = stdout
            self.stderr = ""

    def fake_run(cmd, *args, **kwargs):
        if cmd == ["git", "config", "--get", "user.name"]:
            return Proc(stdout="Jane Developer\n")
        if cmd == ["git", "config", "--get", "user.email"]:
            return Proc(stdout="jane@example.com\n")
        return Proc(returncode=1)

    monkeypatch.setattr(cli.subprocess, "run", fake_run)
    monkeypatch.setattr(cli.sys.stdin, "isatty", lambda: False)
    monkeypatch.setattr(cli, "generated_secret", lambda: "generated-password")

    creds = cli._resolve_wp_admin_credentials(
        argparse.Namespace(wp_user=None, wp_email=None, wp_password=None),
        "example.com",
    )

    assert creds.user == "jane-developer"
    assert creds.email == "jane@example.com"
    assert creds.password == "generated-password"
    assert creds.password_generated is True


def test_site_create_prints_generated_wordpress_password_only_for_new_install(tmp_wpfy_home, monkeypatch, capsys):
    import wpfy.cli as cli

    monkeypatch.setattr(
        cli.site_lifecycle,
        "create_site",
        lambda request, **kwargs: cli.site_lifecycle.CreateSiteResult(
            spec=cli.site_lifecycle.SiteSpec(request.domain, request.flavor, True, False),
            touched=("/tmp/compose.yaml",),
            bootstrap=cli.site_lifecycle.RuntimeResult(0, "wordpress files already bootstrapped", ran=True),
            runtime=cli.site_lifecycle.RuntimeResult(0, "started", ran=True),
            wordpress_message="wordpress installed",
            wordpress_admin_user="admin",
            generated_password="generated-password",
        ),
    )

    result = cli.run(["site", "create", "example.com", "--wp"])
    output = capsys.readouterr().out

    assert result == 0
    assert "=== Site created ===" in output
    assert "Site created" in output
    assert "domain: example.com" in output
    assert "site type: wordpress" in output
    assert "scaffold: updated 1 paths" in output
    assert "bootstrap: OK wordpress files already bootstrapped" in output
    assert "runtime: OK started" in output
    assert "wordpress: wordpress installed" in output
    assert "generated password: generated-password" in output
    assert "next: sign in at https://example.com/wp-admin" in output


def test_site_create_does_not_print_password_for_existing_wordpress_install(monkeypatch, capsys):
    import wpfy.cli as cli

    monkeypatch.setattr(
        cli.site_lifecycle,
        "create_site",
        lambda request, **kwargs: cli.site_lifecycle.CreateSiteResult(
            spec=cli.site_lifecycle.SiteSpec(request.domain, request.flavor, True, False),
            touched=(),
            bootstrap=cli.site_lifecycle.RuntimeResult(0, "wordpress files already bootstrapped", ran=True),
            runtime=cli.site_lifecycle.RuntimeResult(0, "started", ran=True),
            wordpress_message="wordpress already installed",
        ),
    )

    result = cli.run(["site", "create", "example.com", "--wp", "--pass", "do-not-print"])
    output = capsys.readouterr().out

    assert result == 0
    assert "do-not-print" not in output
    assert "Site already up to date" in output
    assert "scaffold: unchanged" in output
    assert "wordpress: wordpress already installed" in output
    assert "next: sign in at https://example.com/wp-admin" in output


def test_site_create_shows_progress_updates_on_tty(monkeypatch, capsys):
    import wpfy.cli as cli

    monkeypatch.setattr(cli.sys.stderr, "isatty", lambda: True)
    def fake_create(request, **kwargs):
        for step in ("scaffold", "bootstrap", "runtime", "wordpress-provision"):
            kwargs["progress"](step)
        return cli.site_lifecycle.CreateSiteResult(
            spec=cli.site_lifecycle.SiteSpec(request.domain, request.flavor, True, False),
            touched=("/tmp/compose.yaml",),
            bootstrap=cli.site_lifecycle.RuntimeResult(0, "bootstrapped", ran=True),
            runtime=cli.site_lifecycle.RuntimeResult(0, "started", ran=True),
            wordpress_message="wordpress installed",
        )

    monkeypatch.setattr(cli.site_lifecycle, "create_site", fake_create)

    result = cli.run(["site", "create", "example.com", "--wp"])
    captured = capsys.readouterr()

    assert result == 0
    assert "Writing site scaffold..." in captured.err
    assert "Bootstrapping site files..." in captured.err
    assert "Starting site runtime..." in captured.err
    assert "Provisioning WordPress core and admin user. This can take a few seconds..." in captured.err


def test_site_create_wpfc_includes_cache_next_step(monkeypatch, capsys):
    import wpfy.cli as cli

    monkeypatch.setattr(
        cli.site_lifecycle,
        "create_site",
        lambda request, **kwargs: cli.site_lifecycle.CreateSiteResult(
            spec=cli.site_lifecycle.SiteSpec(request.domain, request.flavor, True, False),
            touched=("/tmp/compose.yaml",),
            bootstrap=cli.site_lifecycle.RuntimeResult(0, "bootstrapped", ran=True),
            runtime=cli.site_lifecycle.RuntimeResult(0, "started", ran=True),
            wordpress_message="wordpress already installed",
        ),
    )

    result = cli.run(["site", "create", "cache.example.com", "--wpfc"])
    output = capsys.readouterr().out

    assert result == 0
    assert "site type: wordpress" in output
    assert "next: sign in at https://cache.example.com/wp-admin" in output
    assert "next: install and activate the matching cache plugin in WordPress" in output


def test_site_status_uses_human_friendly_summary(monkeypatch, capsys):
    import wpfy.cli as cli
    from wpfy.site_layout import HealthResult

    domain = "status.example.com"

    monkeypatch.setattr(cli, "site_exists", lambda value: True)
    monkeypatch.setattr(
        cli,
        "site_info",
        lambda value: {
            "domain": domain,
            "flavor": "wp",
            "path": f"/opt/wpfy/sites/{domain}",
            "compose": f"/opt/wpfy/sites/{domain}/compose.yaml",
        },
    )
    monkeypatch.setattr(
        cli,
        "site_health",
        lambda value: HealthResult(domain, True, True, True, True, "ready", "web=1 app=1 db=1 redis=0 http=ok"),
    )

    result = cli.run(["site", "status", domain])
    output = capsys.readouterr().out

    assert result == 0
    assert f"=== site status: {domain} ===" in output
    assert "status: ready" in output
    assert "scaffold: yes" in output
    assert "bootstrap: yes" in output
    assert "runtime: yes" in output
    assert "http: yes" in output
    assert "summary: web=1 app=1 db=1 redis=0 http=ok" in output


def test_parser_has_info_command():
    parser = build_parser()
    subparsers = [a for a in parser._actions if hasattr(a, 'choices')]
    commands = set()
    for sp in subparsers:
        if sp.choices:
            commands.update(sp.choices.keys())
    assert "info" in commands
    assert "clean" in commands


def test_site_delete_missing_returns_clean_error(tmp_wpfy_home, monkeypatch):
    monkeypatch.setenv("WPFY_SKIP_RUNTIME", "1")

    result = run(["site", "delete", "missing.example.com", "--force"])

    assert result == 2


def test_rm_alias_requires_force_when_stdin_is_not_tty(monkeypatch, capsys):
    import wpfy.cli as cli

    calls = []
    monkeypatch.setattr(cli, "site_exists", lambda domain: True)
    monkeypatch.setattr(cli, "backup_site", lambda domain: calls.append(("backup", domain)))
    monkeypatch.setattr(cli, "stop_site_runtime", lambda domain, remove_volumes=False: calls.append(("stop", domain)))
    monkeypatch.setattr(cli, "remove_site_scaffold", lambda domain: calls.append(("remove", domain)) or True)
    monkeypatch.setattr(sys.stdin, "isatty", lambda: False)

    result = run(["rm", "example.com"])
    output = capsys.readouterr().out

    assert result == 2
    assert "--force required when stdin is not a TTY" in output
    assert calls == []


def test_rm_alias_force_uses_existing_delete_flow(monkeypatch, capsys):
    import wpfy.cli as cli
    from wpfy.site_layout import RuntimeResult

    calls = []
    monkeypatch.setattr(cli, "site_exists", lambda domain: True)
    monkeypatch.setattr(
        cli,
        "backup_site",
        lambda domain, **kwargs: calls.append(("backup", domain, kwargs))
        or RuntimeResult(0, "backup created", ran=True),
    )
    monkeypatch.setattr(
        cli,
        "stop_site_runtime",
        lambda domain, remove_volumes=False: calls.append(("stop", domain, remove_volumes)) or RuntimeResult(
            0, "stopped", ran=True
        ),
    )
    monkeypatch.setattr(cli, "remove_site_scaffold", lambda domain: calls.append(("remove", domain)) or True)

    result = run(["rm", "example.com", "--force"])
    output = capsys.readouterr().out

    assert result == 0
    assert calls == [
        ("backup", "example.com", {"require_database": True}),
        ("stop", "example.com", True),
        ("remove", "example.com"),
    ]
    assert "=== site deleted ===" in output
    assert "backup: OK backup created" in output
    assert "runtime: OK stopped" in output


def test_site_delete_keeps_scaffold_when_runtime_stop_fails(monkeypatch, capsys):
    import wpfy.cli as cli
    from wpfy.site_layout import RuntimeResult

    removed = []
    monkeypatch.setattr(cli, "site_exists", lambda domain: True)
    monkeypatch.setattr(cli, "backup_site", lambda domain, **kwargs: RuntimeResult(0, "backup created", ran=True))
    monkeypatch.setattr(
        cli,
        "stop_site_runtime",
        lambda domain, remove_volumes=False: RuntimeResult(17, "compose down failed", ran=True),
    )
    monkeypatch.setattr(cli, "remove_site_scaffold", lambda domain: removed.append(domain) or True)
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr("builtins.input", lambda prompt: "yes")

    result = run(["site", "delete", "example.com"])
    output = capsys.readouterr().out

    assert result == 17
    assert removed == []
    assert "runtime: FAIL compose down failed" in output
    assert "files: kept" in output


@pytest.mark.parametrize("force", [False, True])
def test_site_delete_backup_failure_blocks_stop_and_remove(monkeypatch, capsys, force):
    import wpfy.cli as cli
    from wpfy.site_layout import RuntimeResult

    calls = []
    monkeypatch.setattr(cli, "site_exists", lambda domain: True)
    monkeypatch.setattr(
        cli,
        "backup_site",
        lambda domain, **kwargs: RuntimeResult(3, "database backup failed", ran=True),
    )
    monkeypatch.setattr(cli, "stop_site_runtime", lambda *args, **kwargs: calls.append("stop"))
    monkeypatch.setattr(cli, "remove_site_scaffold", lambda *args: calls.append("remove"))
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr("builtins.input", lambda prompt: "yes")

    argv = ["site", "delete", "example.com"] + (["--force"] if force else [])
    result = run(argv)

    assert result == 3
    assert calls == []
    output = capsys.readouterr().out
    assert "backup: FAIL database backup failed" in output
    assert "files: kept" in output


def test_site_delete_skipped_runtime_blocks_remove_even_with_force(monkeypatch, capsys):
    import wpfy.cli as cli
    from wpfy.site_layout import RuntimeResult

    removed = []
    monkeypatch.setattr(cli, "site_exists", lambda domain: True)
    monkeypatch.setattr(cli, "backup_site", lambda domain, **kwargs: RuntimeResult(0, "complete", ran=True))
    monkeypatch.setattr(
        cli,
        "stop_site_runtime",
        lambda *args, **kwargs: RuntimeResult(0, "runtime skipped", skipped=True),
    )
    monkeypatch.setattr(cli, "remove_site_scaffold", lambda domain: removed.append(domain))

    result = run(["site", "delete", "example.com", "--force"])

    assert result == 1
    assert removed == []
    assert "files: kept" in capsys.readouterr().out


def test_wp_alias_uses_existing_wp_cli_path(monkeypatch):
    import wpfy.cli as cli
    from wpfy.site_runtime import ProcessResult

    captured = {}

    def fake_wp(domain, *args, interactive=False):
        captured["domain"] = domain
        captured["args"] = args
        captured["interactive"] = interactive
        return ProcessResult(0, ran=True)

    monkeypatch.setattr(cli, "site_exists", lambda domain: True)
    monkeypatch.setattr(cli, "run_wp_cli", fake_wp)

    result = run(["wp", "example.com", "option", "get", "siteurl"])

    assert result == 0
    assert captured == {
        "domain": "example.com",
        "args": ("option", "get", "siteurl"),
        "interactive": True,
    }


def test_wp_alias_missing_site_exits_two(monkeypatch):
    import wpfy.cli as cli

    monkeypatch.setattr(cli, "site_exists", lambda domain: False)
    monkeypatch.setattr(cli, "run_wp_cli", lambda *args, **kwargs: pytest.fail("runtime should not run"))

    result = run(["wp", "missing.test", "option", "get", "siteurl"])

    assert result == 2


def test_version_command_matches_argparse_version(capsys):
    import wpfy.cli as cli

    result = run(["version"])
    output = capsys.readouterr().out

    assert result == 0
    assert output == f"wpfy {cli.__version__}\n"

    with pytest.raises(SystemExit) as exc_info:
        run(["--version"])
    version_output = capsys.readouterr().out

    assert exc_info.value.code == 0
    assert version_output == f"wpfy {cli.__version__}\n"


def test_up_uses_start_site_runtime(monkeypatch, capsys):
    import wpfy.cli as cli
    from wpfy.site_layout import RuntimeResult

    calls = []
    monkeypatch.setattr(cli, "site_exists", lambda domain: True)
    monkeypatch.setattr(
        cli,
        "start_site_runtime",
        lambda domain: calls.append(domain) or RuntimeResult(7, "started oddly", ran=True),
    )

    result = run(["up", "example.com"])
    output = capsys.readouterr().out

    assert result == 7
    assert calls == ["example.com"]
    assert "=== site up ===" in output
    assert "runtime: FAIL started oddly" in output


def test_up_missing_site_does_not_start_runtime(monkeypatch):
    import wpfy.cli as cli

    monkeypatch.setattr(cli, "site_exists", lambda domain: False)
    monkeypatch.setattr(cli, "start_site_runtime", lambda domain: pytest.fail("runtime should not start"))

    result = run(["up", "missing.test"])

    assert result == 2


def test_up_invalid_domain_does_not_start_runtime(monkeypatch):
    import wpfy.cli as cli

    monkeypatch.setattr(cli, "site_exists", lambda domain: pytest.fail("site_exists should not run"))
    monkeypatch.setattr(cli, "start_site_runtime", lambda domain: pytest.fail("runtime should not start"))

    result = run(["up", "../../etc"])

    assert result == 2


def test_down_uses_stop_site_runtime_without_volumes(monkeypatch, capsys):
    import wpfy.cli as cli
    from wpfy.site_layout import RuntimeResult

    calls = []
    monkeypatch.setattr(cli, "site_exists", lambda domain: True)
    monkeypatch.setattr(
        cli,
        "stop_site_runtime",
        lambda domain, remove_volumes=False: calls.append((domain, remove_volumes)) or RuntimeResult(
            0, "stopped", ran=True
        ),
    )

    result = run(["down", "example.com"])
    output = capsys.readouterr().out

    assert result == 0
    assert calls == [("example.com", False)]
    assert "volumes: kept" in output


def test_down_uses_stop_site_runtime_with_volumes(monkeypatch, capsys):
    import wpfy.cli as cli
    from wpfy.site_layout import RuntimeResult

    calls = []
    monkeypatch.setattr(cli, "site_exists", lambda domain: True)
    monkeypatch.setattr(
        cli,
        "stop_site_runtime",
        lambda domain, remove_volumes=False: calls.append((domain, remove_volumes)) or RuntimeResult(
            0, "stopped", ran=True
        ),
    )

    result = run(["down", "example.com", "--volumes"])
    output = capsys.readouterr().out

    assert result == 0
    assert calls == [("example.com", True)]
    assert "volumes: removed" in output


def test_down_missing_site_does_not_stop_runtime(monkeypatch):
    import wpfy.cli as cli

    monkeypatch.setattr(cli, "site_exists", lambda domain: False)
    monkeypatch.setattr(cli, "stop_site_runtime", lambda *args, **kwargs: pytest.fail("runtime should not stop"))

    result = run(["down", "missing.test"])

    assert result == 2


def test_compose_uses_compose_command_and_preserves_return_code(monkeypatch, capsys):
    import wpfy.cli as cli

    calls = []
    monkeypatch.setattr(cli, "site_exists", lambda domain: True)
    monkeypatch.setattr(
        cli,
        "compose_command",
        lambda domain, *args: calls.append((domain, args)) or FakeProc(17, stdout="compose out\n"),
    )

    result = run(["compose", "example.com", "--", "ps"])
    output = capsys.readouterr().out

    assert result == 17
    assert calls == [("example.com", ("ps",))]
    assert output == "compose out\n"


def test_compose_prints_stderr_when_stdout_is_empty(monkeypatch, capsys):
    import wpfy.cli as cli

    monkeypatch.setattr(cli, "site_exists", lambda domain: True)
    monkeypatch.setattr(cli, "compose_command", lambda domain, *args: FakeProc(1, stderr="compose err\n"))

    result = run(["compose", "example.com", "--", "ps"])
    output = capsys.readouterr().out

    assert result == 1
    assert output == "compose err\n"


def test_compose_requires_arguments_after_domain(monkeypatch):
    import wpfy.cli as cli

    monkeypatch.setattr(cli, "site_exists", lambda domain: True)
    monkeypatch.setattr(cli, "compose_command", lambda *args: pytest.fail("compose should not run"))

    result = run(["compose", "example.com"])

    assert result == 2


def test_compose_missing_site_does_not_call_docker(monkeypatch):
    import wpfy.cli as cli

    monkeypatch.setattr(cli, "site_exists", lambda domain: False)
    monkeypatch.setattr(cli, "compose_command", lambda *args: pytest.fail("compose should not run"))

    result = run(["compose", "missing.test", "--", "ps"])

    assert result == 2


def test_exec_defaults_to_app_service(monkeypatch):
    import wpfy.cli as cli

    calls = []
    monkeypatch.setattr(cli, "site_exists", lambda domain: True)
    monkeypatch.setattr(cli, "compose_command", lambda domain, *args: calls.append((domain, args)) or FakeProc())

    result = run(["exec", "example.com", "--", "php", "-v"])

    assert result == 0
    assert calls == [("example.com", ("exec", "app", "php", "-v"))]


def test_exec_accepts_explicit_service(monkeypatch):
    import wpfy.cli as cli

    calls = []
    monkeypatch.setattr(cli, "site_exists", lambda domain: True)
    monkeypatch.setattr(cli, "compose_command", lambda domain, *args: calls.append((domain, args)) or FakeProc())

    result = run(["exec", "example.com", "web", "--", "nginx", "-v"])

    assert result == 0
    assert calls == [("example.com", ("exec", "web", "nginx", "-v"))]


def test_exec_rejects_invalid_service(monkeypatch):
    import wpfy.cli as cli

    monkeypatch.setattr(cli, "site_exists", lambda domain: True)
    monkeypatch.setattr(cli, "compose_command", lambda *args: pytest.fail("compose should not run"))

    result = run(["exec", "example.com", "unknown", "--", "date"])

    assert result == 2


def test_exec_requires_command(monkeypatch):
    import wpfy.cli as cli

    monkeypatch.setattr(cli, "site_exists", lambda domain: True)
    monkeypatch.setattr(cli, "compose_command", lambda *args: pytest.fail("compose should not run"))

    result = run(["exec", "example.com", "app"])

    assert result == 2


def test_cp_copies_into_site(monkeypatch):
    import wpfy.cli as cli

    calls = []
    monkeypatch.setattr(cli, "site_exists", lambda domain: True)
    monkeypatch.setattr(cli, "compose_command", lambda domain, *args: calls.append((domain, args)) or FakeProc())

    result = run(["cp", "example.com", "./local.txt", "app:/var/www/html/local.txt"])

    assert result == 0
    assert calls == [("example.com", ("cp", "./local.txt", "app:/var/www/html/local.txt"))]


def test_cp_copies_out_of_site(monkeypatch):
    import wpfy.cli as cli

    calls = []
    monkeypatch.setattr(cli, "site_exists", lambda domain: True)
    monkeypatch.setattr(cli, "compose_command", lambda domain, *args: calls.append((domain, args)) or FakeProc())

    result = run(["cp", "example.com", "app:/var/www/html/file.txt", "./file.txt"])

    assert result == 0
    assert calls == [("example.com", ("cp", "app:/var/www/html/file.txt", "./file.txt"))]


def test_cp_missing_site_does_not_call_compose(monkeypatch):
    import wpfy.cli as cli

    monkeypatch.setattr(cli, "site_exists", lambda domain: False)
    monkeypatch.setattr(cli, "compose_command", lambda *args: pytest.fail("compose should not run"))

    result = run(["cp", "missing.test", "./local.txt", "app:/var/www/html/local.txt"])

    assert result == 2


def test_cp_rejects_dangerous_broad_path(monkeypatch):
    import wpfy.cli as cli

    monkeypatch.setattr(cli, "site_exists", lambda domain: True)
    monkeypatch.setattr(cli, "compose_command", lambda *args: pytest.fail("compose should not run"))

    result = run(["cp", "example.com", "/", "app:/var/www/html/root-copy"])

    assert result == 2


def test_pull_defaults_to_all_site_services(monkeypatch):
    import wpfy.cli as cli

    calls = []
    monkeypatch.setattr(cli, "site_exists", lambda domain: True)
    monkeypatch.setattr(cli, "compose_command", lambda domain, *args: calls.append((domain, args)) or FakeProc())

    result = run(["pull", "example.com"])

    assert result == 0
    assert calls == [("example.com", ("pull",))]


def test_pull_all_uses_plain_pull(monkeypatch):
    import wpfy.cli as cli

    calls = []
    monkeypatch.setattr(cli, "site_exists", lambda domain: True)
    monkeypatch.setattr(cli, "compose_command", lambda domain, *args: calls.append((domain, args)) or FakeProc())

    result = run(["pull", "example.com", "--all"])

    assert result == 0
    assert calls == [("example.com", ("pull",))]


def test_pull_service_uses_service_arg(monkeypatch):
    import wpfy.cli as cli

    calls = []
    monkeypatch.setattr(cli, "site_exists", lambda domain: True)
    monkeypatch.setattr(cli, "compose_command", lambda domain, *args: calls.append((domain, args)) or FakeProc())

    result = run(["pull", "example.com", "--service", "app"])

    assert result == 0
    assert calls == [("example.com", ("pull", "app"))]


def test_pull_rejects_invalid_service(monkeypatch):
    import wpfy.cli as cli

    monkeypatch.setattr(cli, "site_exists", lambda domain: True)
    monkeypatch.setattr(cli, "compose_command", lambda *args: pytest.fail("compose should not run"))

    result = run(["pull", "example.com", "--service", "unknown"])

    assert result == 2


def test_config_status_prints_sanitized_summary(tmp_path, monkeypatch, capsys):
    import wpfy.cli as cli

    env_file = tmp_path / ".env"
    env_file.write_text(
        "\n".join([
            "DOMAIN=example.com",
            "SITE_FLAVOR=wpredis",
            "PHP_VERSION=8.4",
            "DB_PASSWORD=db-secret",
            "DB_ROOT_PASSWORD=root-secret",
            "SFTP_PASSWORD=sftp-secret",
            "SFTP_PORT=2222",
            "LETSENCRYPT_MODE=default",
            "PROXIED=1",
        ]),
        encoding="utf-8",
    )
    monkeypatch.setattr(cli, "site_exists", lambda domain: True)
    monkeypatch.setattr(cli, "env_path", lambda domain: env_file)
    monkeypatch.setattr(cli, "compose_path", lambda domain: tmp_path / "compose.yaml")

    result = run(["config", "example.com"])
    output = capsys.readouterr().out

    assert result == 0
    assert "=== site config ===" in output
    assert "domain: example.com" in output
    assert "flavor: wpredis" in output
    assert "database password: configured" in output
    assert "sftp password: configured" in output
    assert "DB_PASSWORD=" not in output
    assert "DB_ROOT_PASSWORD=" not in output
    assert "SFTP_PASSWORD=" not in output
    assert "db-secret" not in output
    assert "root-secret" not in output
    assert "sftp-secret" not in output


def test_config_update_routes_through_update_site(monkeypatch):
    import wpfy.cli as cli

    captured = []

    def fake_update(request):
        captured.append(request)
        return cli.site_lifecycle.UpdateSiteResult(
            spec=cli.site_lifecycle.SiteSpec(request.domain, "wp", True, False),
            touched=("/tmp/compose.yaml",),
            runtime=cli.site_lifecycle.RuntimeResult(0, "started", ran=True),
            changes=("php 8.3→8.4",),
        )

    monkeypatch.setattr(cli, "site_exists", lambda domain: True)
    monkeypatch.setattr(cli.site_lifecycle, "update_site", fake_update)

    result = run(["config", "example.com", "--php", "8.4"])

    assert result == 0
    assert captured[0].domain == "example.com"
    assert captured[0].php_version == "8.4"


def test_config_update_routes_wpredis_letsencrypt_and_proxied(monkeypatch):
    import wpfy.cli as cli

    captured = []

    def fake_update(request):
        captured.append(request)
        return cli.site_lifecycle.UpdateSiteResult(
            spec=cli.site_lifecycle.SiteSpec(request.domain, "wpredis", True, True),
            touched=(),
            runtime=cli.site_lifecycle.RuntimeResult(0, "started", ran=True),
            changes=(),
        )

    monkeypatch.setattr(cli, "site_exists", lambda domain: True)
    monkeypatch.setattr(cli.site_lifecycle, "update_site", fake_update)

    assert run(["config", "example.com", "--wpredis"]) == 0
    assert run(["config", "example.com", "--letsencrypt", "off"]) == 0
    assert run(["config", "example.com", "--proxied"]) == 0
    assert run(["config", "example.com", "--no-proxied"]) == 0

    assert captured[0].wpredis is True
    assert captured[1].letsencrypt == "off"
    assert captured[2].proxied_override is True
    assert captured[3].proxied_override is False


def test_config_missing_site_does_not_update(monkeypatch):
    import wpfy.cli as cli

    monkeypatch.setattr(cli, "site_exists", lambda domain: False)
    monkeypatch.setattr(cli.site_lifecycle, "update_site", lambda request: pytest.fail("update should not run"))

    result = run(["config", "missing.test", "--php", "8.4"])

    assert result == 2


def test_config_invalid_domain_does_not_update(monkeypatch):
    import wpfy.cli as cli

    monkeypatch.setattr(cli, "site_exists", lambda domain: pytest.fail("site_exists should not run"))
    monkeypatch.setattr(cli.site_lifecycle, "update_site", lambda request: pytest.fail("update should not run"))

    result = run(["config", "../../etc", "--php", "8.4"])

    assert result == 2


def test_config_password_prompt_passes_password_without_printing(monkeypatch, capsys):
    import wpfy.cli as cli

    captured = []

    def fake_update(request):
        captured.append(request)
        return cli.site_lifecycle.UpdateSiteResult(
            spec=cli.site_lifecycle.SiteSpec(request.domain, "wp", True, False),
            touched=(),
            runtime=cli.site_lifecycle.RuntimeResult(0, "started", ran=True),
            changes=(),
            password_summary="OK password updated for admin",
        )

    monkeypatch.setattr(cli, "site_exists", lambda domain: True)
    monkeypatch.setattr(cli.sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(cli.getpass, "getpass", lambda prompt: "prompt-secret")
    monkeypatch.setattr(cli.site_lifecycle, "update_site", fake_update)

    result = run(["config", "example.com", "--password"])
    output = capsys.readouterr().out

    assert result == 0
    assert captured[0].password == "prompt-secret"
    assert "prompt-secret" not in output


def test_config_password_stdin_passes_password_without_printing(monkeypatch, capsys):
    import wpfy.cli as cli

    captured = []

    def fake_update(request):
        captured.append(request)
        return cli.site_lifecycle.UpdateSiteResult(
            spec=cli.site_lifecycle.SiteSpec(request.domain, "wp", True, False),
            touched=(),
            runtime=cli.site_lifecycle.RuntimeResult(0, "started", ran=True),
            changes=(),
            password_summary="OK password updated for admin",
        )

    monkeypatch.setattr(cli, "site_exists", lambda domain: True)
    monkeypatch.setattr(cli.sys, "stdin", io.StringIO("stdin-secret\n"))
    monkeypatch.setattr(cli.site_lifecycle, "update_site", fake_update)

    result = run(["config", "example.com", "--password-stdin"])
    output = capsys.readouterr().out

    assert result == 0
    assert captured[0].password == "stdin-secret"
    assert "stdin-secret" not in output


def test_config_password_does_not_accept_plain_argument():
    with pytest.raises(SystemExit) as exc_info:
        run(["config", "example.com", "--password", "secret"])
    assert exc_info.value.code == 2


def test_edit_print_path_does_not_print_contents(tmp_path, monkeypatch, capsys):
    import wpfy.cli as cli

    env_file = tmp_path / ".env"
    env_file.write_text("DOMAIN=example.com\nDB_PASSWORD=secret\n", encoding="utf-8")
    monkeypatch.setattr(cli, "site_exists", lambda domain: True)
    monkeypatch.setattr(cli, "env_path", lambda domain: env_file)

    result = run(["edit", "example.com", "--print-path"])
    output = capsys.readouterr().out

    assert result == 0
    assert output == f"{env_file}\n"
    assert "DB_PASSWORD" not in output
    assert "secret" not in output


def test_edit_refuses_non_tty_without_editor_or_refresh(tmp_path, monkeypatch):
    import wpfy.cli as cli

    env_file = tmp_path / ".env"
    env_file.write_text("DOMAIN=example.com\n", encoding="utf-8")
    monkeypatch.delenv("EDITOR", raising=False)
    monkeypatch.delenv("VISUAL", raising=False)
    monkeypatch.setattr(cli, "site_exists", lambda domain: True)
    monkeypatch.setattr(cli, "env_path", lambda domain: env_file)
    monkeypatch.setattr(cli.sys.stdin, "isatty", lambda: False)
    monkeypatch.setattr(cli.subprocess, "run", lambda *args, **kwargs: pytest.fail("editor should not run"))
    monkeypatch.setattr(cli, "ensure_site_scaffold", lambda spec: pytest.fail("refresh should not run"))

    result = run(["edit", "example.com"])

    assert result == 2


def test_edit_success_backs_up_opens_editor_and_refreshes(tmp_path, monkeypatch, capsys):
    import wpfy.cli as cli

    env_file = tmp_path / ".env"
    env_file.write_text("DOMAIN=example.com\nSITE_FLAVOR=wp\nDB_PASSWORD=secret\n", encoding="utf-8")
    calls = []

    monkeypatch.setenv("EDITOR", "fake-editor")
    monkeypatch.setattr(cli, "site_exists", lambda domain: True)
    monkeypatch.setattr(cli, "env_path", lambda domain: env_file)
    monkeypatch.setattr(cli.sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(cli.sys.stdout, "isatty", lambda: True)
    monkeypatch.setattr(cli.subprocess, "run", lambda cmd, **kwargs: calls.append(cmd) or FakeProc())
    monkeypatch.setattr(
        cli,
        "ensure_site_scaffold",
        lambda spec: calls.append(("refresh", spec.domain)) or ["compose.yaml"],
    )

    result = run(["edit", "example.com"])
    output = capsys.readouterr().out

    backups = list(tmp_path.glob(".env.bak-*"))
    assert result == 0
    assert calls == [["fake-editor", str(env_file)], ("refresh", "example.com")]
    assert len(backups) == 1
    assert "backup:" in output
    assert "refresh: updated 1 paths" in output
    assert "secret" not in output


def test_refresh_single_regenerates_without_restart(tmp_path, monkeypatch, capsys):
    import wpfy.cli as cli

    env_file = tmp_path / ".env"
    env_file.write_text("DOMAIN=example.com\nSITE_FLAVOR=html\n", encoding="utf-8")
    calls = []
    monkeypatch.setattr(cli, "site_exists", lambda domain: True)
    monkeypatch.setattr(cli, "env_path", lambda domain: env_file)
    monkeypatch.setattr(cli, "ensure_site_scaffold", lambda spec: calls.append(spec.domain) or ["compose.yaml", ".env"])
    monkeypatch.setattr(cli, "start_site_runtime", lambda domain: pytest.fail("runtime should not start"))

    result = run(["refresh", "example.com"])
    output = capsys.readouterr().out

    assert result == 0
    assert calls == ["example.com"]
    assert "scaffold: updated 2 paths" in output
    assert "runtime: skipped" in output


def test_refresh_restart_preserves_runtime_exit_code(tmp_path, monkeypatch):
    import wpfy.cli as cli
    from wpfy.site_layout import RuntimeResult

    env_file = tmp_path / ".env"
    env_file.write_text("DOMAIN=example.com\nSITE_FLAVOR=html\n", encoding="utf-8")
    monkeypatch.setattr(cli, "site_exists", lambda domain: True)
    monkeypatch.setattr(cli, "env_path", lambda domain: env_file)
    monkeypatch.setattr(cli, "ensure_site_scaffold", lambda spec: [])
    monkeypatch.setattr(cli, "start_site_runtime", lambda domain: RuntimeResult(9, "failed", ran=True))

    result = run(["refresh", "example.com", "--restart"])

    assert result == 9


def test_refresh_all_uses_sorted_domains_and_returns_nonzero_on_failure(tmp_path, monkeypatch, capsys):
    import wpfy.cli as cli

    env_files = {
        "a.example.com": tmp_path / "a.env",
        "b.example.com": tmp_path / "b.env",
    }
    env_files["a.example.com"].write_text("DOMAIN=a.example.com\nSITE_FLAVOR=html\n", encoding="utf-8")
    env_files["b.example.com"].write_text("DOMAIN=wrong.example.com\nSITE_FLAVOR=html\n", encoding="utf-8")
    calls = []

    monkeypatch.setattr(cli, "list_sites", lambda: [{"domain": "b.example.com"}, {"domain": "a.example.com"}])
    monkeypatch.setattr(cli, "site_exists", lambda domain: True)
    monkeypatch.setattr(cli, "env_path", lambda domain: env_files[domain])

    def fake_scaffold(spec):
        calls.append(spec.domain)
        return []

    monkeypatch.setattr(cli, "ensure_site_scaffold", fake_scaffold)

    result = run(["refresh", "all"])
    output = capsys.readouterr().out

    assert result == 2
    assert calls == ["a.example.com"]
    assert output.index("a.example.com: OK") < output.index("b.example.com: FAIL")


def test_refresh_missing_site_does_not_mutate(monkeypatch):
    import wpfy.cli as cli

    monkeypatch.setattr(cli, "site_exists", lambda domain: False)
    monkeypatch.setattr(cli, "ensure_site_scaffold", lambda spec: pytest.fail("refresh should not run"))

    result = run(["refresh", "missing.test"])

    assert result == 2


def test_refresh_invalid_config_does_not_mutate(tmp_path, monkeypatch):
    import wpfy.cli as cli

    env_file = tmp_path / ".env"
    env_file.write_text("DOMAIN=example.com\nSITE_FLAVOR=html\nSITE_UID=bad\n", encoding="utf-8")
    monkeypatch.setattr(cli, "site_exists", lambda domain: True)
    monkeypatch.setattr(cli, "env_path", lambda domain: env_file)
    monkeypatch.setattr(cli, "ensure_site_scaffold", lambda spec: pytest.fail("refresh should not run"))

    result = run(["refresh", "example.com"])

    assert result == 2


def test_refresh_preserves_unmanaged_env_keys(tmp_wpfy_home, monkeypatch, capsys):
    import wpfy.cli
    import wpfy.site_layout

    importlib.reload(wpfy.site_layout)
    importlib.reload(wpfy.cli)

    domain = "preserve.example.com"
    spec = wpfy.site_layout.SiteSpec(domain=domain, flavor="wp", use_mysql=True, use_redis=False)
    wpfy.site_layout.ensure_site_scaffold(spec)
    env_file = wpfy.site_layout.env_path(domain)
    with env_file.open("a", encoding="utf-8") as handle:
        handle.write("CUSTOM_OPERATOR_KEY=keep-me\n")

    result = wpfy.cli.run(["refresh", domain])
    output = capsys.readouterr().out

    assert result == 0
    assert "CUSTOM_OPERATOR_KEY=keep-me" in env_file.read_text(encoding="utf-8")
    assert "CUSTOM_OPERATOR_KEY" not in output
    assert "keep-me" not in output


def test_site_ssl_preflight_only_failure_exits_nonzero(monkeypatch):
    import wpfy.cli
    from wpfy.certificate_lifecycle import SSLPreflightResult

    monkeypatch.setattr(
        wpfy.cli,
        "preflight_ssl",
        lambda domain: SSLPreflightResult(domain, (), (), ("203.0.113.10",), (), False, "preflight failed"),
    )

    result = wpfy.cli.run(["site", "ssl", "bad.example.com", "--letsencrypt", "--preflight-only"])

    assert result == 2


def test_site_ssl_wildcard_requires_cloudflare_config_before_site_mutation(tmp_wpfy_home, monkeypatch, capsys):
    import wpfy.cli as cli
    from wpfy.certificate_lifecycle import SSLPreflightResult

    importlib.reload(cli.dns)
    importlib.reload(cli.site_lifecycle)
    monkeypatch.setattr(
        cli.site_lifecycle,
        "preflight_ssl",
        lambda domain: SSLPreflightResult(domain, ("203.0.113.10",), (), ("203.0.113.10",), (), True, "ok"),
    )
    monkeypatch.setattr(cli.site_lifecycle, "site_info", lambda domain: pytest.fail("site should not mutate"))

    result = cli.run(["site", "ssl", "example.com", "--letsencrypt", "wildcard", "--dns", "cloudflare"])
    output = capsys.readouterr().out

    assert result == 2
    assert "Cloudflare DNS is not configured" in output


def test_site_create_proxied_preflight_sets_spec_proxied(monkeypatch):
    import wpfy.cli as cli

    captured = {}
    def fake_create(request, **kwargs):
        captured["request"] = request
        return cli.site_lifecycle.CreateSiteResult(
            spec=cli.site_lifecycle.SiteSpec(request.domain, request.flavor, True, False, proxied=True),
            touched=(),
            bootstrap=cli.site_lifecycle.RuntimeResult(0, "ok", ran=True),
            runtime=cli.site_lifecycle.RuntimeResult(0, "started", ran=True),
        )

    monkeypatch.setattr(cli.site_lifecycle, "create_site", fake_create)

    result = cli.run(["site", "create", "example.com", "--wp", "--letsencrypt"])

    assert result == 0
    assert captured["request"].proxied_override is None


def test_site_create_no_proxied_override_forces_direct(monkeypatch):
    import wpfy.cli as cli

    captured = {}
    def fake_create(request, **kwargs):
        captured["request"] = request
        return cli.site_lifecycle.CreateSiteResult(
            spec=cli.site_lifecycle.SiteSpec(request.domain, request.flavor, True, False),
            touched=(),
            bootstrap=cli.site_lifecycle.RuntimeResult(0, "ok", ran=True),
            runtime=cli.site_lifecycle.RuntimeResult(0, "started", ran=True),
        )

    monkeypatch.setattr(cli.site_lifecycle, "create_site", fake_create)

    result = cli.run(["site", "create", "example.com", "--wp", "--letsencrypt", "--no-proxied"])

    assert result == 0
    assert captured["request"].proxied_override is False


def test_debug_reports_issued_cert_with_unknown_expiry(tmp_wpfy_home, monkeypatch):
    import subprocess
    from pathlib import Path

    import wpfy.cli as cli
    from wpfy.site_layout import RuntimeResult

    domain = "example.com"
    monkeypatch.setattr(cli.operational_inspection, "PATHS", tmp_wpfy_home)
    site_root = Path(tmp_wpfy_home.sites_dir) / domain
    site_root.mkdir(parents=True)
    (site_root / "compose.yaml").write_text("services: {}\n", encoding="utf-8")

    class Proc:
        returncode = 0
        stdout = "{}"
        stderr = ""

    monkeypatch.setattr(subprocess, "run", lambda *args, **kwargs: Proc())
    monkeypatch.setattr(
        cli.operational_inspection,
        "http_probe_site",
        lambda domain: RuntimeResult(0, "http probe passed", ran=True),
    )
    monkeypatch.setattr(cli.operational_inspection, "get_cert_info", lambda domain: {"status": "issued"})
    monkeypatch.setattr(cli.operational_inspection, "cert_expiry_days", lambda domain: None)
    monkeypatch.setattr(cli.operational_inspection, "site_info", lambda domain: {"flavor": "html"})

    checks = cli.operational_inspection.site_diagnostics(domain)

    assert any(
        check.name == "ssl expiry"
        and check.ok is None
        and check.message == "certificate found; expiry unavailable"
        for check in checks
    )


def test_secure_fails_on_loose_env_permissions(tmp_wpfy_home, monkeypatch, capsys):
    import wpfy.cli
    import wpfy.site_layout

    importlib.reload(wpfy.site_layout)
    importlib.reload(wpfy.cli)

    class Proc:
        returncode = 1
        stdout = ""
        stderr = ""

    monkeypatch.setattr(wpfy.cli.operational_inspection.subprocess, "run", lambda *args, **kwargs: Proc())
    spec = wpfy.site_layout.SiteSpec(domain="loose.example.com", flavor="html", use_mysql=False, use_redis=False)
    wpfy.site_layout.ensure_site_scaffold(spec)
    wpfy.site_layout.env_path("loose.example.com").chmod(0o644)

    result = wpfy.cli.run(["secure", "loose.example.com"])
    output = capsys.readouterr().out

    assert result == 1
    assert "[FAIL] .env: perms 0o644 (expected 0o600)" in output


def test_secure_passes_on_private_env_permissions(tmp_wpfy_home, monkeypatch, capsys):
    import wpfy.cli
    import wpfy.site_layout

    importlib.reload(wpfy.site_layout)
    importlib.reload(wpfy.cli)

    class Proc:
        returncode = 1
        stdout = ""
        stderr = ""

    monkeypatch.setattr(wpfy.cli.operational_inspection.subprocess, "run", lambda *args, **kwargs: Proc())
    spec = wpfy.site_layout.SiteSpec(domain="private.example.com", flavor="html", use_mysql=False, use_redis=False)
    wpfy.site_layout.ensure_site_scaffold(spec)

    result = wpfy.cli.run(["secure", "private.example.com"])
    output = capsys.readouterr().out

    assert result == 0
    assert "[PASS] .env: perms 0o600" in output
    assert "result: PASS" in output
    assert stat.S_IMODE(wpfy.site_layout.env_path("private.example.com").stat().st_mode) == 0o600


def test_secure_warns_on_sftp_host_port_without_secret_output(tmp_wpfy_home, monkeypatch, capsys):
    import wpfy.cli
    import wpfy.site_layout

    importlib.reload(wpfy.site_layout)
    importlib.reload(wpfy.cli)

    domain = "sftp-secure.example.com"
    project = wpfy.site_layout.domain_to_project(domain)

    class Proc:
        def __init__(self, returncode=1, stdout="", stderr=""):
            self.returncode = returncode
            self.stdout = stdout
            self.stderr = stderr

    def fake_run(cmd, *args, **kwargs):
        if cmd[:2] == ["docker", "inspect"]:
            return Proc(1, json.dumps([{
                "Name": f"/{project}-sftp",
                "HostConfig": {
                    "Privileged": False,
                    "PortBindings": {"22/tcp": [{"HostIp": "127.0.0.1", "HostPort": "2222"}]},
                },
                "Config": {"User": "1000"},
            }]))
        return Proc()

    monkeypatch.setattr(wpfy.cli.operational_inspection.subprocess, "run", fake_run)
    spec = wpfy.site_layout.SiteSpec(domain=domain, flavor="html", use_mysql=False, use_redis=False)
    wpfy.site_layout.ensure_site_scaffold(spec)

    result = wpfy.cli.run(["secure", domain])
    output = capsys.readouterr().out

    assert result == 0
    assert f"[WARN] {project}-sftp: host port bindings: 22/tcp" in output
    assert "SFTP_PASSWORD" not in output
    assert "secret" not in output


def test_secure_reports_container_hardening_baseline(tmp_wpfy_home, monkeypatch, capsys):
    import wpfy.cli
    import wpfy.site_layout

    importlib.reload(wpfy.site_layout)
    importlib.reload(wpfy.cli)

    domain = "hardened.example.com"
    project = wpfy.site_layout.domain_to_project(domain)

    class Proc:
        def __init__(self, returncode=1, stdout="", stderr=""):
            self.returncode = returncode
            self.stdout = stdout
            self.stderr = stderr

    def fake_run(cmd, *args, **kwargs):
        if cmd[:2] == ["docker", "inspect"]:
            return Proc(1, json.dumps([{
                "Name": f"/{project}-web",
                "HostConfig": {
                    "Privileged": False,
                    "SecurityOpt": ["no-new-privileges:true"],
                    "CapDrop": ["NET_RAW"],
                    "PidsLimit": 256,
                    "Memory": 268435456,
                    "LogConfig": {
                        "Type": "json-file",
                        "Config": {"max-size": "10m", "max-file": "3"},
                    },
                    "PortBindings": {},
                },
                "Config": {"User": "101"},
            }]))
        return Proc()

    monkeypatch.setattr(wpfy.cli.operational_inspection.subprocess, "run", fake_run)
    spec = wpfy.site_layout.SiteSpec(domain=domain, flavor="html", use_mysql=False, use_redis=False)
    wpfy.site_layout.ensure_site_scaffold(spec)

    result = wpfy.cli.run(["secure", domain])
    output = capsys.readouterr().out

    assert result == 0
    assert f"[PASS] {project}-web: no-new-privileges enabled" in output
    assert f"[PASS] {project}-web: raw network capability dropped" in output
    assert f"[PASS] {project}-web: pids_limit=256" in output
    assert f"[PASS] {project}-web: memory limit configured" in output
    assert f"[PASS] {project}-web: log rotation configured" in output


@dataclass(frozen=True, slots=True)
class DiskUsage:
    total: int
    used: int
    free: int


def test_healthcheck_disk_pass_warn_and_fail(monkeypatch, capsys):
    import wpfy.cli as cli

    monkeypatch.setattr(cli.shutil, "disk_usage", lambda path: DiskUsage(100, 42, 58))
    result = run(["healthcheck", "disk", "--path", "/", "--warn", "80", "--fail", "90"])
    output = capsys.readouterr().out
    assert result == 0
    assert "[PASS] disk: 42.0% used at /" in output

    monkeypatch.setattr(cli.shutil, "disk_usage", lambda path: DiskUsage(100, 85, 15))
    result = run(["healthcheck", "disk", "--warn", "80", "--fail", "90"])
    output = capsys.readouterr().out
    assert result == 0
    assert "[WARN] disk: 85.0% used at /" in output

    monkeypatch.setattr(cli.shutil, "disk_usage", lambda path: DiskUsage(100, 95, 5))
    result = run(["healthcheck", "disk", "--warn", "80", "--fail", "90"])
    output = capsys.readouterr().out
    assert result == 1
    assert "[FAIL] disk: 95.0% used at /" in output


def test_healthcheck_disk_invalid_thresholds_return_two():
    assert run(["healthcheck", "disk", "--warn", "95", "--fail", "90"]) == 2


def test_healthcheck_load_pass_fail_and_unavailable(monkeypatch, capsys):
    import wpfy.cli as cli

    monkeypatch.setattr(cli.os, "getloadavg", lambda: (2.0, 1.0, 0.5))
    monkeypatch.setattr(cli.os, "cpu_count", lambda: 4)
    result = run(["healthcheck", "load", "--warn", "1.5", "--fail", "3.0"])
    output = capsys.readouterr().out
    assert result == 0
    assert "[PASS] load: 0.50 per CPU" in output

    monkeypatch.setattr(cli.os, "getloadavg", lambda: (12.0, 1.0, 0.5))
    result = run(["healthcheck", "load", "--warn", "1.5", "--fail", "3.0"])
    output = capsys.readouterr().out
    assert result == 1
    assert "[FAIL] load: 3.00 per CPU" in output

    def unavailable():
        raise OSError("unsupported")

    monkeypatch.setattr(cli.os, "getloadavg", unavailable)
    result = run(["healthcheck", "load"])
    output = capsys.readouterr().out
    assert result == 0
    assert "[WARN] load: load average unavailable" in output


def test_healthcheck_load_invalid_thresholds_return_two():
    assert run(["healthcheck", "load", "--warn", "3", "--fail", "1"]) == 2


def test_healthcheck_system_renders_labels_and_failure(monkeypatch, capsys):
    import wpfy.cli as cli
    from wpfy.operational_inspection import InspectionCheck

    monkeypatch.delenv("WPFY_SKIP_RUNTIME", raising=False)
    monkeypatch.setattr(
        cli.operational_inspection,
        "system_diagnostics",
        lambda: (
            InspectionCheck("Docker", True, "Docker daemon responding"),
            InspectionCheck("Traefik", None, "status unavailable"),
            InspectionCheck("registry", False, "registry mismatch"),
        ),
    )

    result = run(["healthcheck", "system"])
    output = capsys.readouterr().out

    assert result == 1
    assert "[PASS] Docker: Docker daemon responding" in output
    assert "[WARN] Traefik: status unavailable" in output
    assert "[FAIL] registry: registry mismatch" in output
    assert "secret" not in output.lower()


def test_healthcheck_system_runtime_skip_is_warning(monkeypatch, capsys):
    monkeypatch.setenv("WPFY_SKIP_RUNTIME", "1")

    result = run(["healthcheck", "system"])
    output = capsys.readouterr().out

    assert result == 0
    assert "[WARN] runtime: runtime skipped by WPFY_SKIP_RUNTIME=1" in output


def test_healthcheck_app_single_site_success_and_failure(monkeypatch, capsys):
    import wpfy.cli as cli
    from wpfy.site_layout import HealthResult

    monkeypatch.setattr(cli, "site_exists", lambda domain: True)
    monkeypatch.setattr(
        cli,
        "site_health",
        lambda domain: HealthResult(domain, True, True, True, True, "ready", "web=1 app=1 http=ok"),
    )
    result = run(["healthcheck", "app", "example.com"])
    output = capsys.readouterr().out
    assert result == 0
    assert "example.com: PASS ready - web=1 app=1 http=ok" in output

    monkeypatch.setattr(
        cli,
        "site_health",
        lambda domain: HealthResult(domain, True, True, False, False, "down", "no healthy compose services"),
    )
    result = run(["healthcheck", "app", "example.com"])
    output = capsys.readouterr().out
    assert result == 1
    assert "example.com: FAIL down - no healthy compose services" in output


def test_healthcheck_app_missing_or_invalid_site_does_not_probe(monkeypatch):
    import wpfy.cli as cli

    monkeypatch.setattr(cli, "site_exists", lambda domain: False)
    monkeypatch.setattr(cli, "site_health", lambda domain: pytest.fail("site_health should not run"))
    assert run(["healthcheck", "app", "missing.test"]) == 2

    monkeypatch.setattr(cli, "site_exists", lambda domain: pytest.fail("site_exists should not run"))
    assert run(["healthcheck", "app", "../../etc"]) == 2


def test_healthcheck_app_all_sites_sorted_and_nonzero_on_failure(monkeypatch, capsys):
    import wpfy.cli as cli
    from wpfy.site_layout import HealthResult

    monkeypatch.setattr(cli, "list_sites", lambda: [{"domain": "z.example.com"}, {"domain": "a.example.com"}])
    monkeypatch.setattr(cli, "site_exists", lambda domain: True)

    def fake_health(domain):
        if domain == "z.example.com":
            return HealthResult(domain, True, True, False, False, "down", "runtime failed")
        return HealthResult(domain, True, True, True, True, "ready", "runtime ready")

    monkeypatch.setattr(cli, "site_health", fake_health)

    result = run(["healthcheck", "app", "--all-sites"])
    output = capsys.readouterr().out

    assert result == 1
    assert output.index("a.example.com: PASS ready") < output.index("z.example.com: FAIL down")


def test_healthcheck_app_all_sites_empty(monkeypatch, capsys):
    import wpfy.cli as cli

    monkeypatch.setattr(cli, "list_sites", lambda: [])

    result = run(["healthcheck", "app", "--all-sites"])
    output = capsys.readouterr().out

    assert result == 0
    assert "no managed sites found" in output


def test_healthcheck_all_and_default_use_component_results(monkeypatch, capsys):
    import wpfy.cli as cli

    monkeypatch.setattr(cli, "_healthcheck_disk", lambda *args: cli.CommandResult("disk ok"))
    monkeypatch.setattr(cli, "_healthcheck_load", lambda *args: cli.CommandResult("load ok"))
    monkeypatch.setattr(cli, "_healthcheck_system", lambda: cli.CommandResult("system fail", exit_code=1))
    monkeypatch.setattr(cli, "_healthcheck_all_sites", lambda: cli.CommandResult("sites ok"))

    result = run(["healthcheck", "all"])
    output = capsys.readouterr().out
    assert result == 1
    assert "disk ok" in output
    assert "system fail" in output

    result = run(["healthcheck"])
    output = capsys.readouterr().out
    assert result == 1
    assert "sites ok" in output


def test_motd_prints_safe_summary(monkeypatch, capsys):
    import wpfy.cli as cli
    from wpfy.operational_inspection import AggregateInfo

    monkeypatch.setattr(
        cli.operational_inspection,
        "aggregate_info",
        lambda: AggregateInfo(
            sites=(
                {"domain": "example.com", "flavor": "wp", "ssl_enabled": True, "cache_type": "redis"},
                {"domain": "second.test", "flavor": "html", "ssl": "disabled", "redis": "0"},
            ),
            traefik_message="Traefik running",
            docker_version="24.0.0",
        ),
    )

    result = run(["motd"])
    output = capsys.readouterr().out

    assert result == 0
    assert "version:" in output
    assert "docker: 24.0.0" in output
    assert "traefik: Traefik running" in output
    assert "sites: 2 managed" in output
    assert "- example.com wp ssl=enabled cache=redis" in output
    assert "password" not in output.lower()
    assert "secret" not in output.lower()


def test_motd_compact_handles_unavailable_docker(monkeypatch, capsys):
    import wpfy.cli as cli
    from wpfy.operational_inspection import AggregateInfo

    monkeypatch.setattr(
        cli.operational_inspection,
        "aggregate_info",
        lambda: AggregateInfo(sites=(), traefik_message="traefik status unavailable", docker_version="unavailable"),
    )

    result = run(["motd", "--compact"])
    output = capsys.readouterr().out

    assert result == 0
    assert "docker=unavailable" in output
    assert "warnings=2" in output


def test_utility_password_length_and_no_symbols(capsys):
    result = run(["utility", "password", "--length", "32"])
    output = capsys.readouterr().out.strip()
    assert result == 0
    assert len(output) == 32

    result = run(["utility", "password", "--length", "32", "--no-symbols"])
    output = capsys.readouterr().out.strip()
    assert result == 0
    assert len(output) == 32
    assert all(ch.isalnum() for ch in output)

    assert run(["utility", "password", "--length", "8"]) == 2


def test_utility_token_length_validation(capsys):
    result = run(["utility", "token", "--bytes", "32"])
    output = capsys.readouterr().out.strip()
    assert result == 0
    assert output

    assert run(["utility", "token", "--bytes", "8"]) == 2


def test_utility_username_normalizes_values(capsys):
    result = run(["utility", "username", "Arnab Mohapatra"])
    output = capsys.readouterr().out
    assert result == 0
    assert output == "arnab-mohapatra\n"

    result = run(["utility", "username", "!!!"])
    output = capsys.readouterr().out
    assert result == 0
    assert output == "admin\n"


def test_utility_uid_existing_and_missing_sites(tmp_path, monkeypatch, capsys):
    import wpfy.cli as cli

    env_file = tmp_path / ".env"
    env_file.write_text("SITE_UID=100001\n", encoding="utf-8")

    monkeypatch.setattr(cli, "site_exists", lambda domain: domain == "example.com")
    monkeypatch.setattr(cli, "env_path", lambda domain: env_file)

    result = run(["utility", "uid", "example.com"])
    output = capsys.readouterr().out
    assert result == 0
    assert "project: example-com" in output
    assert "site_uid: 100001" in output

    result = run(["utility", "uid", "missing.test"])
    output = capsys.readouterr().out
    assert result == 0
    assert "project: missing-test" in output
    assert "site_uid: not allocated" in output

    assert run(["utility", "uid", "../../etc"]) == 2


def test_utility_htpasswd_generated_and_stdin(monkeypatch, capsys):
    result = run(["utility", "htpasswd", "--username", "admin"])
    output = capsys.readouterr().out
    assert result == 0
    assert "username: admin" in output
    assert "password: " in output
    assert "htpasswd: admin:{SHA}" in output

    monkeypatch.setattr(sys, "stdin", io.StringIO("stdin-secret\n"))
    result = run(["utility", "htpasswd", "--username", "admin", "--password-stdin"])
    output = capsys.readouterr().out
    assert result == 0
    assert output.startswith("htpasswd: admin:{SHA}")
    assert "stdin-secret" not in output

    assert run(["utility", "htpasswd", "--username", "bad:name"]) == 2


def test_info_and_update_actions_are_mutually_exclusive():
    parser = build_parser()
    with pytest.raises(SystemExit) as info_exit:
        parser.parse_args(["info", "example.com", "--nginx", "--php"])
    with pytest.raises(SystemExit) as update_exit:
        parser.parse_args(["update", "--check", "--force"])
    assert info_exit.value.code == update_exit.value.code == 2


def test_info_service_flag_requires_domain(capsys):
    assert run(["info", "--nginx"]) == 2
    assert "requires a domain" in capsys.readouterr().out


def test_site_list_reconciles_before_rendering(monkeypatch, capsys):
    import wpfy.cli as cli

    calls = []
    monkeypatch.setattr(cli.registry, "sync_from_filesystem", lambda: calls.append("sync"))
    monkeypatch.setattr(
        cli.registry,
        "list_sites",
        lambda: calls.append("list") or [
            {"domain": "example.com", "flavor": "wpredis", "ssl_enabled": True, "cache_type": "redis"}
        ],
    )

    assert run(["site", "list"]) == 0
    assert calls == ["sync", "list"]
    assert "example.com\twpredis\tssl=enabled\tcache=redis" in capsys.readouterr().out


def test_site_list_reports_reconciliation_failure(monkeypatch, capsys):
    import wpfy.cli as cli

    monkeypatch.setattr(cli.registry, "sync_from_filesystem", lambda: (_ for _ in ()).throw(OSError("read failed")))
    monkeypatch.setattr(cli.registry, "list_sites", lambda: pytest.fail("stale registry must not render"))

    assert run(["site", "list"]) == 1
    assert "reconciliation failed: read failed" in capsys.readouterr().out


@pytest.mark.parametrize("flag", ["--enabled", "--disabled"])
def test_site_list_rejects_removed_flags(flag):
    with pytest.raises(SystemExit) as exc_info:
        build_parser().parse_args(["site", "list", flag])
    assert exc_info.value.code == 2


@pytest.mark.parametrize("installed", ["9.0.dev1", "3.0", "malformed-local"])
def test_update_check_reports_version_mismatch_neutrally(installed, monkeypatch, capsys):
    import wpfy.cli as cli

    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self):
            return b'{"info":{"version":"2.0"}}'

    monkeypatch.setattr(cli.importlib.metadata, "version", lambda name: installed)
    monkeypatch.setattr(cli, "urlopen", lambda *args, **kwargs: Response())

    assert run(["update", "--check"]) == 0
    output = capsys.readouterr().out
    assert f"installed: {installed}" in output
    assert "latest published: 2.0" in output
    assert "versions differ" in output
    assert "update available" not in output


def test_update_force_reports_command_completion_without_unproven_transition(monkeypatch, capsys):
    import wpfy.cli as cli

    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self):
            return b'{"info":{"version":"2.0"}}'

    monkeypatch.setattr(cli.importlib.metadata, "version", lambda name: "1.0")
    monkeypatch.setattr(cli, "urlopen", lambda *args, **kwargs: Response())
    monkeypatch.setattr(cli.subprocess, "run", lambda *args, **kwargs: FakeProc())

    assert run(["update", "--force"]) == 0
    output = capsys.readouterr().out
    assert "pip upgrade command completed" in output
    assert "1.0 -> 2.0" not in output


def test_runtime_and_certificate_annotations_are_truthful():
    from typing import get_type_hints

    import wpfy.certificate_lifecycle as certificates
    import wpfy.cli as cli
    from wpfy.site_runtime import RuntimeResult

    assert get_type_hints(cli._step_status)["result"] is RuntimeResult
    assert get_type_hints(cli._step_line)["result"] is RuntimeResult
    assert get_type_hints(cli._format_site_create_result)["bootstrap"] is RuntimeResult
    assert get_type_hints(certificates.get_cert_info)["return"] is dict


def test_make_site_handler_rejects_unknown_name():
    import wpfy.cli as cli

    with pytest.raises(ValueError, match="unsupported site handler"):
        cli.make_site_handler("scaffold")
